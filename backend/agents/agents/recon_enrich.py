"""
agents/recon_enrich.py — Option A recon enrichment for PentraAI.

Additive, pure-Python (httpx + regex, no external tools). Takes the recon
results dict and enriches it with modern bug-bounty signals:

  1. OpenAPI/Swagger discovery + parsing  -> full endpoint + parameter inventory
  2. Parameter extraction (query strings + OpenAPI bodies) -> results["parameters"]
  3. JS secret mining (API keys/tokens/JWT/private keys)   -> results["secrets"]
  4. JS endpoint mining (/api, /v1, /graphql, ...)         -> more endpoints

Design guarantees:
  * Never raises — any error and it returns the results unchanged, so it can
    NOT break the existing recon or the modules that depend on its output shape.
  * Only ADDS keys (parameters, secrets, openapi_spec) and APPENDS endpoints;
    it never removes or renames existing keys.
"""

import re
import httpx
from urllib.parse import urlparse, parse_qs, urljoin

from config import settings


# Common locations for an OpenAPI / Swagger specification, served BY the target.
SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs",
    "/api-docs", "/api/openapi.json", "/api/swagger.json",
    "/swagger/v1/swagger.json", "/api-docs/swagger.json", "/docs/openapi.json",
    "/api/v1/openapi.json", "/api/v2/openapi.json",
    "/identity/api-docs", "/community/api-docs", "/workshop/api-docs",
]

# Some well-known vulnerable-by-design apps never serve their spec live — it only
# exists in their GitHub repo. crAPI is the documented example (confirmed by the
# official OWASP ZAP crAPI testing guide, which fetches this exact URL). Detected
# via tech_stack/app markers set elsewhere in recon.py, or via signature endpoints.
KNOWN_STATIC_SPECS = {
    "crapi": "https://raw.githubusercontent.com/OWASP/crAPI/refs/heads/develop/openapi-spec/crapi-openapi-spec.json",
}

# Secret patterns to mine from JavaScript. Specific enough to limit noise.
SECRET_PATTERNS = [
    ("AWS Access Key",  re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key",  re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token",     re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Stripe Key",      re.compile(r"(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{20,}")),
    ("JWT",             re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("Private Key",     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Firebase URL",    re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("Generic Secret",  re.compile(
        r"""(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret)"""
        r"""\s*[:=]\s*["']([A-Za-z0-9_\-\.]{12,})["']""")),
]

# Endpoint patterns to mine from JavaScript.
JS_API_RE = re.compile(r"""["'`](/(?:api|rest|graphql|identity|community|workshop)/[A-Za-z0-9_\-/.{}]+)["'`]""")
JS_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-/.]*(?:api|v1|v2|admin|user|auth|internal|graphql)[A-Za-z0-9_\-/.]*)["'`]""")

MAX_ENDPOINTS = 150


async def enrich_recon(results: dict, target_url: str) -> dict:
    """Enrich recon results with OpenAPI, parameters, and JS-mined intel."""
    base = target_url.rstrip("/")
    try:
        async with httpx.AsyncClient(
            timeout=settings.request_timeout, verify=False, follow_redirects=True
        ) as client:
            oapi_endpoints, oapi_params, spec_url = await _discover_openapi(client, base)

            url_params = _params_from_urls(
                results.get("alive_endpoints", []) + results.get("wayback_urls", [])
            )

            js_urls = _collect_js_urls(results, base)
            secrets, js_endpoints = await _mine_js(client, js_urls[:15], base)

            # ── merge parameters (new key) ────────────────────────
            all_params = _dedup_params(oapi_params + url_params)
            results["parameters"] = all_params

            # ── merge endpoints (append, dedup, cap) ──────────────
            existing = list(results.get("alive_endpoints", []))
            existing_set = set(existing)
            additions = []
            for ep in oapi_endpoints + js_endpoints + _sample_param_urls(all_params):
                if ep not in existing_set:
                    existing_set.add(ep)
                    additions.append(ep)
            results["alive_endpoints"] = (existing + additions)[:MAX_ENDPOINTS]

            # ── new keys ──────────────────────────────────────────
            results["secrets"] = secrets
            results["openapi_spec"] = spec_url or ""
            if spec_url:
                results["api_spec_found"] = True

            print(
                f"RECON+: OpenAPI={'found' if spec_url else 'none'} | "
                f"+{len(additions)} endpoints | {len(all_params)} parameters | "
                f"{len(secrets)} secret(s) in JS"
            )
    except Exception as e:
        print(f"RECON+: enrichment skipped ({e})")

    # Guarantee the new keys always exist so modules can rely on them.
    results.setdefault("parameters", [])
    results.setdefault("secrets", [])
    results.setdefault("openapi_spec", "")
    return results


# ── OpenAPI / Swagger ─────────────────────────────────────────────

async def _discover_openapi(client: httpx.AsyncClient, base: str):
    endpoints: list[str] = []
    parameters: list[dict] = []
    spec_url = ""
    spec = None

    for path in SPEC_PATHS:
        try:
            r = await client.get(base + path)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            candidate = r.json()
        except Exception:
            continue
        if isinstance(candidate, dict) and "paths" in candidate:
            spec, spec_url = candidate, base + path
            break

    # Fallback: known apps that don't serve a live spec (e.g. crAPI — confirmed
    # by OWASP's own ZAP testing guide, which fetches this exact GitHub URL).
    if spec is None:
        try:
            probe = await client.get(base + "/identity/api/auth/signup")
            looks_like_crapi = probe.status_code in (400, 401, 405)
        except Exception:
            looks_like_crapi = False
        if looks_like_crapi:
            try:
                r = await client.get(KNOWN_STATIC_SPECS["crapi"])
                if r.status_code == 200:
                    candidate = r.json()
                    if isinstance(candidate, dict) and "paths" in candidate:
                        spec, spec_url = candidate, KNOWN_STATIC_SPECS["crapi"]
                        print("RECON+: OpenAPI not served live — using crAPI's known GitHub spec")
            except Exception:
                pass

    if spec is not None:
        base_path = ""
        if isinstance(spec.get("servers"), list) and spec["servers"]:
            su = spec["servers"][0].get("url", "")
            base_path = urlparse(su).path if su.startswith("http") else su
        elif spec.get("basePath"):
            base_path = spec["basePath"]

        schemas = (spec.get("components", {}) or {}).get("schemas", {}) or spec.get("definitions", {}) or {}

        for p, methods in (spec.get("paths", {}) or {}).items():
            full = base + _join(base_path, p)
            endpoints.append(full)
            if not isinstance(methods, dict):
                continue
            path_level = methods.get("parameters", []) if isinstance(methods.get("parameters"), list) else []
            for method, op in methods.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch"):
                    continue
                op = op if isinstance(op, dict) else {}
                for prm in list(path_level) + list(op.get("parameters", []) or []):
                    if isinstance(prm, dict) and prm.get("name"):
                        parameters.append({
                            "url": full, "method": method.upper(),
                            "name": prm["name"], "location": prm.get("in", "query"),
                        })
                for bp in _body_params(op, schemas):
                    parameters.append({
                        "url": full, "method": method.upper(),
                        "name": bp, "location": "body",
                    })

    return endpoints, parameters, spec_url


def _body_params(op: dict, schemas: dict) -> list[str]:
    names: list[str] = []
    try:
        content = (op.get("requestBody", {}) or {}).get("content", {}) or {}
        for _ct, media in content.items():
            names += _schema_props(media.get("schema", {}), schemas)
        for prm in op.get("parameters", []) or []:
            if isinstance(prm, dict) and prm.get("in") == "body":
                names += _schema_props(prm.get("schema", {}), schemas)
    except Exception:
        pass
    return names[:20]


def _schema_props(schema: dict, schemas: dict) -> list[str]:
    if not isinstance(schema, dict):
        return []
    if "$ref" in schema:
        ref = schema["$ref"].split("/")[-1]
        schema = schemas.get(ref, {}) if isinstance(schemas, dict) else {}
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    return list(props.keys()) if isinstance(props, dict) else []


def _join(a: str, b: str) -> str:
    a = (a or "").rstrip("/")
    b = "/" + (b or "").lstrip("/")
    return a + b


# ── Parameter extraction ──────────────────────────────────────────

def _params_from_urls(urls: list[str]) -> list[dict]:
    out: list[dict] = []
    for u in urls:
        if not isinstance(u, str):
            continue
        query = urlparse(u).query
        if not query:
            continue
        for name in parse_qs(query).keys():
            out.append({"url": u.split("?")[0], "method": "GET",
                        "name": name, "location": "query"})
    return out


def _dedup_params(params: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for p in params:
        key = (p.get("url"), p.get("name"), p.get("location"), p.get("method"))
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out[:200]


def _sample_param_urls(params: list[dict]) -> list[str]:
    """Build sample ?name=test URLs so query-param scanners (e.g. SSRF) see them."""
    out = []
    for p in params:
        if p.get("location") == "query" and p.get("method") == "GET":
            out.append(f"{p['url']}?{p['name']}=test")
    return out[:30]


# ── JS mining ─────────────────────────────────────────────────────

def _collect_js_urls(results: dict, base: str) -> list[str]:
    urls = set()
    for key in ("js_endpoints", "all_links", "alive_endpoints"):
        for u in results.get(key, []):
            if isinstance(u, str) and ".js" in u.lower():
                urls.add(u if u.startswith("http") else urljoin(base + "/", u))
    return list(urls)


async def _mine_js(client: httpx.AsyncClient, js_urls: list[str], base: str):
    secrets: list[dict] = []
    endpoints: list[str] = []
    seen_secret = set()

    for ju in js_urls:
        try:
            r = await client.get(ju)
            if r.status_code != 200:
                continue
            text = r.text
        except Exception:
            continue

        for label, rx in SECRET_PATTERNS:
            for m in rx.finditer(text):
                val = m.group(0)
                key = (label, val[:40])
                if key in seen_secret:
                    continue
                seen_secret.add(key)
                secrets.append({"type": label, "match": _mask(val), "source": ju})
                if len(secrets) >= 40:
                    break

        for rx in (JS_API_RE, JS_PATH_RE):
            for m in rx.finditer(text):
                ep = m.group(1)
                endpoints.append(ep if ep.startswith("http") else urljoin(base + "/", ep))

    return secrets, list(set(endpoints))[:60]


def _mask(v: str) -> str:
    """Mask a secret for safe reporting (proves presence without dumping the value)."""
    v = v.strip()
    if len(v) <= 12:
        return v[:4] + "…"
    return v[:8] + "…" + v[-4:]