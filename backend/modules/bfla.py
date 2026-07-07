"""
modules/bfla.py — Broken Function-Level Authorization (BFLA)
                  OWASP API5:2023 / A01:2025 Broken Access Control

Generic and bug-bounty-oriented — NOT hardcoded to crAPI. It finds privileged
functions a normal (or unauthenticated) user should not be able to call.

Method:
  1. Establish a normal-user session (User B token) and also test UNAUTHENTICATED.
  2. Build privileged-endpoint candidates from:
       - recon's discovered endpoints whose path looks privileged
         (/admin, /manage, /internal, users/all, orders/all, export, ...),
       - a small built-in probe list of common admin paths.
  3. Call each with (a) the normal-user token and (b) no token.
  4. A properly-secured privileged function returns 401/403. A 200/201 with
     privileged content = BFLA. The LLM (with bfla.md knowledge) confirms the
     response really exposes a privileged function, filtering public endpoints.

Returns findings in PentraAI's standard shape.
"""

import json
import httpx
from urllib.parse import urlparse

from llm import call_llm
from config import settings
from knowledge import knowledge_section
from modules.auto_accounts import create_two_accounts, login_one_account


# Strong privileged-path markers (kept deliberately specific to limit false positives).
PRIVILEGED_MARKERS = [
    "/admin", "administrator", "/manage", "/management", "/internal", "/moderator",
    "/staff", "superuser", "/root/", "/actuator", "/console", "/sysadmin",
    "users/all", "user/all", "allusers", "all_users", "/users?", "orders/all",
    "all_orders", "accounts/all", "/export", "/backup", "/audit", "/config",
    "/settings/all", "/dashboard/admin", "approve", "/ban", "/suspend", "/promote",
    "grant", "revoke", "/role", "/permission", "/impersonate", "/metrics",
]

# Common admin paths to probe even if recon did not surface them.
COMMON_ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/users", "/admin/dashboard", "/administrator",
    "/api/admin", "/api/admin/users", "/api/v1/admin", "/api/users", "/api/users/all",
    "/manage", "/management", "/internal", "/actuator", "/actuator/env",
    "/api/config", "/console", "/dashboard",
]

# Bodies/markers indicating a genuinely privileged response worth escalating to the LLM.
PRIV_CONTENT_HINTS = [
    "role", "is_admin", "isadmin", "admin", "password", "users", "email",
    "orders", "accounts", "permission", "config", "secret", "token", "all",
]


def _looks_privileged(url: str) -> bool:
    u = url.lower()
    return any(marker in u for marker in PRIVILEGED_MARKERS)


async def run_bfla(
    recon_data: dict,
    target_url: str,
    user_a_email: str = "",
    user_a_password: str = "",
    user_b_email: str = "",
    user_b_password: str = "",
) -> list[dict]:
    """Detect Broken Function-Level Authorization. Returns a list of findings."""
    target_url = target_url.rstrip("/")
    kb = knowledge_section("bfla")
    findings: list[dict] = []

    # ── Establish a normal-user session (best effort) ─────────────
    lowpriv_token = ""
    if user_b_email and user_b_password:
        lowpriv_token, _ = await login_one_account(target_url, user_b_email, user_b_password)
    elif user_a_email and user_a_password:
        lowpriv_token, _ = await login_one_account(target_url, user_a_email, user_a_password)
    else:
        try:
            accounts = await create_two_accounts(target_url, recon_data)
            if accounts.get("success"):
                lowpriv_token = accounts.get("token_b") or accounts.get("token_a") or ""
                print(f"BFLA: normal-user session ready ({accounts.get('user_b_email', accounts.get('user_a_email',''))})")
            else:
                print(f"BFLA: no accounts ({accounts.get('error','')}); testing UNAUTHENTICATED only")
        except Exception as e:
            print(f"BFLA: account setup error: {e}; testing UNAUTHENTICATED only")

    # ── Build privileged candidate list ──────────────────────────
    candidates = _build_candidates(recon_data, target_url)
    print(f"BFLA: {len(candidates)} privileged-looking endpoint(s) to test")

    async with httpx.AsyncClient(timeout=settings.request_timeout,
                                 follow_redirects=False, verify=False) as client:
        for cand in candidates[:20]:
            finding = await _test_endpoint(client, cand, lowpriv_token, kb)
            if finding:
                findings.append(finding)
                print(f"BFLA: VULNERABLE -> {cand['method']} {cand['url']}")
                if len(findings) >= 5:
                    break
            else:
                print(f"BFLA: ok -> {cand['method']} {cand['url']}")

    if not findings:
        print("BFLA: no broken function-level authorization detected")
    return findings


def _build_candidates(recon_data: dict, target_url: str) -> list[dict]:
    """Collect privileged-looking endpoints from recon + a common-admin-path probe list."""
    candidates: list[dict] = []
    seen: set = set()

    def add(url: str, method: str = "GET"):
        # Dedupe by normalized path (ignore ?query-string and trailing slash) so that
        # e.g. orders/all, orders/all?limit=test and orders/all?offset=test collapse to
        # ONE candidate instead of producing three near-identical findings.
        p = urlparse(url)
        key = (p.scheme, p.netloc, p.path.rstrip("/"), method)
        if key not in seen:
            seen.add(key)
            candidates.append({"url": url, "method": method})

    # 1) Recon-discovered endpoints that look privileged
    for ep in recon_data.get("alive_endpoints", []):
        full = ep if ep.startswith("http") else (target_url + "/" + ep.lstrip("/"))
        if _looks_privileged(full):
            add(full, "GET")

    # 2) Common admin paths (probe even if not discovered)
    for path in COMMON_ADMIN_PATHS:
        add(target_url + path, "GET")

    return candidates


async def _test_endpoint(
    client: httpx.AsyncClient,
    cand: dict,
    lowpriv_token: str,
    kb: str,
) -> dict | None:
    """Call a privileged endpoint as a normal user and unauthenticated; judge the result."""
    url, method = cand["url"], cand["method"]

    async def _call(headers):
        try:
            r = await client.request(method, url, headers=headers)
            return {"status": r.status_code, "text": r.text[:1200]}
        except Exception:
            return None

    # As a normal user
    lowpriv = await _call({"Authorization": f"Bearer {lowpriv_token}"} if lowpriv_token else {})
    # Unauthenticated
    unauth = await _call({})

    # Pick the most permissive successful response to evaluate.
    for label, resp, token_used in (("normal-user", lowpriv, bool(lowpriv_token)),
                                    ("unauthenticated", unauth, False)):
        if not resp:
            continue
        status = resp["status"]
        if status not in (200, 201):
            continue  # correctly denied (401/403) or absent (404) → not BFLA here
        body = resp["text"]
        if not _has_priv_content(body):
            continue  # 200 but nothing privileged (likely a public/empty page)
        if _is_empty_data(body):
            continue  # 200 but no actual records exposed (empty collection) → not a real bypass

        verdict = _ask_bfla_verdict(url, method, label, status, body, kb)
        if verdict.get("vulnerable"):
            return _finding(url, method, label, status, body, token_used,
                            verdict.get("severity", "high"),
                            verdict.get("reasoning", ""))
    return None


def _has_priv_content(body: str) -> bool:
    if not body:
        return False
    low = body.lower()
    # Require some structured/privileged signal to avoid flagging blank SPA pages.
    return any(h in low for h in PRIV_CONTENT_HINTS) and len(body.strip()) > 15


def _json_is_empty(data) -> bool:
    """True when a parsed JSON body carries no actual records."""
    if data in (None, {}, [], ""):
        return True
    if isinstance(data, list):
        return len(data) == 0
    if isinstance(data, dict):
        collections = [v for v in data.values() if isinstance(v, list)]
        if collections and all(len(c) == 0 for c in collections):
            return True
    return False


def _is_empty_data(body: str) -> bool:
    """A 200 whose body exposes no real records (empty collections like
    {"orders":[],"count":0}) is not a privilege bypass, so it should not be a
    finding. Genuinely privileged responses are usually long and arrive truncated,
    so they fail to parse here and are safely treated as non-empty."""
    if not body or not body.strip():
        return True
    try:
        return _json_is_empty(json.loads(body.strip()))
    except Exception:
        return False


def _ask_bfla_verdict(url, method, caller, status, body, kb) -> dict:
    prompt = f"""You are a security analyst confirming Broken Function-Level Authorization (BFLA).

{kb[:4000]}

A {caller} caller (who should NOT have privileged access) called:
  {method} {url}
and received HTTP {status}. Response body (truncated):
{body[:800]}

Decide if this is BFLA: a genuinely PRIVILEGED function/endpoint (admin namespace, or an
admin/other-role action, or data belonging to all users/other roles) that this caller should
have been denied (expected 401/403) but was allowed.

Flag as BFLA ONLY IF the endpoint is genuinely privileged AND the response exposes privileged
data or a privileged action. Do NOT flag public endpoints, health checks, login/register,
generic content, or anything a normal user is meant to access.

Return ONLY JSON:
{{"vulnerable": true or false, "severity": "critical" or "high" or "medium", "reasoning": "one sentence citing the evidence"}}"""
    try:
        return json.loads(call_llm(prompt, expect_json=True))
    except Exception:
        # Conservative fallback: only trust obvious admin-namespace successes.
        return {"vulnerable": _looks_privileged(url),
                "severity": "high",
                "reasoning": "Privileged-namespace endpoint returned success to a caller who should be denied (heuristic)."}


def _finding(url, method, caller, status, body, token_used, severity, reasoning) -> dict:
    return {
        "vulnerability": "Broken Function-Level Authorization (BFLA)",
        "owasp": "A01:2025 — Broken Access Control",
        "endpoint": url,
        "severity": severity,
        "needs_help": False,
        "evidence": {
            "request": {
                "method": method,
                "url": url,
                "caller": caller,
                "authenticated": token_used,
                "headers": {"Authorization": "Bearer <normal-user-token>"} if token_used else {},
            },
            "response": {"status": status, "body": body[:600]},
        },
        "ai_reasoning": reasoning,
    }