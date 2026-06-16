"""
auto_accounts.py — Autonomous Account Creation
The agent automatically:
  1. Detects the target app (Juice Shop, DVWA, generic)
  2. Finds the registration endpoint
  3. Figures out required fields
  4. Creates two test accounts
  5. Logs both in and gets tokens

If anything fails, returns a short specific message
telling the user exactly what went wrong.
"""

import json
import uuid
import httpx
from bs4 import BeautifulSoup
from llm import call_llm
from config import settings


TEST_PASSWORD = "PentraAI_Test@123"


def _make_email(suffix: str) -> str:
    short = uuid.uuid4().hex[:6]
    return f"pentraai_{suffix}_{short}@test.com"


# ── App fingerprinting ────────────────────────────────────────────

async def _detect_app(client: httpx.AsyncClient, base_url: str) -> str:
    """Detect which known app we are targeting."""
    try:
        r = await client.get(base_url)
        body = r.text.lower()
        if "juice" in body or "owasp juice" in body:
            return "juiceshop"
        if "dvwa" in body or "damn vulnerable" in body:
            return "dvwa"
    except Exception:
        pass
    return "generic"


# ── Known app configs ─────────────────────────────────────────────

KNOWN_APPS = {
    "juiceshop": {
        "register_url": "/api/Users",
        "login_url":    "/rest/user/login",
        "token_path":   ["authentication", "token"],
        "userid_path":  ["authentication", "bid"],
    },
}


def _juiceshop_register_body(email: str, pwd: str) -> dict:
    return {
        "email":    email,
        "password": pwd,
        "passwordRepeat": pwd,
        "securityQuestion": {
            "id": 1,
            "question": "Your eldest siblings middle name?",
            "createdAt": "2024-01-01",
            "updatedAt": "2024-01-01"
        },
        "securityAnswer": "pentraai"
    }


def _generic_login_body(email: str, pwd: str) -> dict:
    return {"email": email, "password": pwd}


# ── Main entry point ──────────────────────────────────────────────

async def create_two_accounts(target_url: str, recon_data: dict) -> dict:
    """
    Fully autonomous account creation.
    Returns success dict with both tokens, or failure with help message.
    """
    async with httpx.AsyncClient(
        timeout=settings.request_timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        app_type = await _detect_app(client, target_url)
        print(f"AUTO-ACCOUNTS: Detected app → {app_type}")

        if app_type == "juiceshop":
            return await _juiceshop_flow(client, target_url)
        else:
            return await _generic_flow(client, target_url, recon_data)


# ── Juice Shop flow ───────────────────────────────────────────────

async def _juiceshop_flow(client: httpx.AsyncClient, base_url: str) -> dict:
    """Hardcoded flow for OWASP Juice Shop."""
    email_a = _make_email("a")
    email_b = _make_email("b")
    reg_url   = base_url + "/api/Users"
    login_url = base_url + "/rest/user/login"

    for label, email in [("User A", email_a), ("User B", email_b)]:
        print(f"AUTO-ACCOUNTS: Registering {label} ({email})...")
        body = _juiceshop_register_body(email, TEST_PASSWORD)
        ok, err = await _post(client, reg_url, body)
        if not ok:
            return _needs_help(
                error=f"Juice Shop registration failed for {label}: {err}",
                help_message=(
                    f"Could not register {label} at {reg_url}. "
                    f"Reason: {err}. "
                    "Please create two accounts manually in Juice Shop "
                    "and provide their emails and passwords."
                )
            )

    # Login both
    results = {}
    for label, email in [("a", email_a), ("b", email_b)]:
        print(f"AUTO-ACCOUNTS: Logging in User {label.upper()} ({email})...")
        body = _generic_login_body(email, TEST_PASSWORD)
        r_ok, r_body, err = await _post_get_response(client, login_url, body)
        if not r_ok:
            return _needs_help(
                error=f"Juice Shop login failed: {err}",
                help_message=(
                    f"Accounts created but login failed. "
                    f"Reason: {err}. "
                    f"Emails: {email_a}, {email_b}. Password: {TEST_PASSWORD}"
                )
            )
        token   = _dig(r_body, ["authentication", "token"])
        user_id = _dig(r_body, ["authentication", "bid"])
        if not token:
            return _needs_help(
                error=f"No token in Juice Shop login response: {str(r_body)[:200]}",
                help_message=(
                    "Logged in but could not extract token. "
                    "Please provide credentials manually."
                )
            )
        results[label] = {"token": token, "user_id": str(user_id or ""), "email": email}

    print("AUTO-ACCOUNTS: Both accounts ready ✓")
    return {
        "success":      True,
        "token_a":      results["a"]["token"],
        "user_a_email": results["a"]["email"],
        "user_a_id":    results["a"]["user_id"],
        "token_b":      results["b"]["token"],
        "user_b_email": results["b"]["email"],
        "user_b_id":    results["b"]["user_id"],
        "error":        None,
        "needs_help":   False,
        "help_message": None,
    }


# ── Generic flow ──────────────────────────────────────────────────

async def _generic_flow(
    client: httpx.AsyncClient,
    base_url: str,
    recon_data: dict,
) -> dict:
    """Generic flow for unknown apps."""

    # Find registration endpoint
    reg_info = await _discover_registration(client, base_url, recon_data)
    if not reg_info["found"]:
        return _needs_help(
            error=reg_info["error"],
            help_message=(
                "Could not find a registration endpoint. "
                "Please provide two test account credentials manually."
            )
        )

    email_a = _make_email("a")
    email_b = _make_email("b")

    for label, email in [("User A", email_a), ("User B", email_b)]:
        print(f"AUTO-ACCOUNTS: Registering {label} ({email})...")
        body = _build_reg_body(reg_info["fields"], email, TEST_PASSWORD)
        ok, err = await _post(client, reg_info["url"], body)
        if not ok:
            return _needs_help(
                error=f"Registration failed for {label}: {err}",
                help_message=f"Could not create {label}. Reason: {err}."
            )

    results = {}
    for label, email in [("a", email_a), ("b", email_b)]:
        print(f"AUTO-ACCOUNTS: Logging in User {label.upper()} ({email})...")
        token, uid, err = await _find_and_login(
            client, base_url, reg_info, email, TEST_PASSWORD
        )
        if not token:
            return _needs_help(
                error=f"Login failed for User {label.upper()}: {err}",
                help_message=(
                    f"Accounts created but login failed. "
                    f"Reason: {err}. "
                    f"Emails: {email_a}, {email_b}. Password: {TEST_PASSWORD}"
                )
            )
        results[label] = {"token": token, "user_id": uid, "email": email}

    print("AUTO-ACCOUNTS: Both accounts ready ✓")
    return {
        "success":      True,
        "token_a":      results["a"]["token"],
        "user_a_email": results["a"]["email"],
        "user_a_id":    results["a"]["user_id"],
        "token_b":      results["b"]["token"],
        "user_b_email": results["b"]["email"],
        "user_b_id":    results["b"]["user_id"],
        "error":        None,
        "needs_help":   False,
        "help_message": None,
    }


# ── Login helpers ─────────────────────────────────────────────────

async def _find_and_login(
    client: httpx.AsyncClient,
    base_url: str,
    reg_info: dict,
    email: str,
    password: str,
) -> tuple[str, str, str]:
    """Try common login endpoints. Returns (token, user_id, error)."""

    candidates = [
        base_url + "/rest/user/login",
        base_url + "/api/auth/login",
        base_url + "/api/login",
        base_url + "/login",
        base_url + "/api/users/login",
        base_url + "/api/v1/auth/login",
        base_url + "/auth/login",
    ]

    # Also try derived from registration URL
    reg_url = reg_info.get("url", "")
    for old, new in [("register", "login"), ("signup", "login"),
                     ("Users", "login"), ("users", "login")]:
        derived = reg_url.replace(old, new)
        if derived not in candidates:
            candidates.append(derived)

    cred_formats = [
        {"email": email, "password": password},
        {"username": email, "password": password},
    ]

    last_error = "No login endpoint responded with a token"

    for url in candidates:
        for creds in cred_formats:
            try:
                r = await client.post(
                    url, json=creds,
                    headers={"Content-Type": "application/json"}
                )
                print(f"AUTO-ACCOUNTS: {url} → HTTP {r.status_code}")

                if r.status_code in [200, 201]:
                    try:
                        body = r.json()
                    except Exception:
                        continue

                    token   = _extract_token(body, r)
                    user_id = _extract_userid(body)

                    if token:
                        print(f"AUTO-ACCOUNTS: Token found at {url} ✓")
                        return token, user_id, ""

                    last_error = f"HTTP 200 at {url} but no token found. Body: {str(body)[:150]}"

            except Exception as e:
                last_error = str(e)
                continue

    return "", "", last_error


async def _discover_registration(
    client: httpx.AsyncClient,
    base_url: str,
    recon_data: dict,
) -> dict:
    """Probe common paths to find a registration endpoint."""
    paths = [
        "/api/Users", "/api/auth/register", "/api/register",
        "/register", "/api/users/register", "/api/v1/auth/register",
        "/api/users", "/signup", "/api/signup", "/api/v1/users",
    ]

    for path in paths:
        url = base_url + path
        try:
            r = await client.get(url)
            if r.status_code not in [404]:
                fields = await _detect_fields(client, url)
                if fields:
                    return {"found": True, "url": url, "fields": fields,
                            "method": "POST", "error": None}
        except Exception:
            pass

    # Ask LLM
    llm_result = await _ask_llm_reg(base_url, recon_data)
    if llm_result:
        return llm_result

    return {"found": False, "url": None, "fields": {}, "method": "POST",
            "error": "Could not find registration endpoint."}


async def _detect_fields(client: httpx.AsyncClient, url: str) -> dict:
    """Send empty POST and use LLM to detect required fields."""
    try:
        r = await client.post(url, json={})
        prompt = f"""Registration API at {url} returned this for empty body:
Status: {r.status_code}
Response: {r.text[:400]}

What string fields does it need? Return ONLY JSON like:
{{"email": "email", "password": "password"}}
Return {{}} if unknown."""
        raw = call_llm(prompt, expect_json=True)
        return json.loads(raw)
    except Exception:
        return {}


async def _ask_llm_reg(base_url: str, recon_data: dict) -> dict | None:
    """Ask LLM to suggest registration endpoint from recon."""
    try:
        prompt = f"""Find a user registration endpoint for {base_url}.
Known endpoints: {recon_data.get('alive_endpoints', [])[:15]}
Tech: {recon_data.get('tech_stack', {})}
Return ONLY JSON: {{"url": "/api/auth/register", "fields": {{"email": "email", "password": "password"}}, "confidence": "high"}}
If unknown: {{"url": null, "fields": {{}}, "confidence": "none"}}"""
        raw = call_llm(prompt, expect_json=True)
        data = json.loads(raw)
        if data.get("url") and data.get("confidence") != "none":
            url = base_url + data["url"] if data["url"].startswith("/") else data["url"]
            return {"found": True, "url": url,
                    "fields": data.get("fields", {"email": "email", "password": "password"}),
                    "method": "POST", "error": None}
    except Exception:
        pass
    return None


# ── HTTP helpers ──────────────────────────────────────────────────

async def _post(client: httpx.AsyncClient, url: str, body: dict) -> tuple[bool, str]:
    """POST and return (success, error_msg)."""
    try:
        r = await client.post(url, json=body,
                              headers={"Content-Type": "application/json"})
        if r.status_code in [200, 201, 204, 409]:
            return True, ""
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)


async def _post_get_response(
    client: httpx.AsyncClient, url: str, body: dict
) -> tuple[bool, dict, str]:
    """POST and return (success, parsed_body, error)."""
    try:
        r = await client.post(url, json=body,
                              headers={"Content-Type": "application/json"})
        print(f"AUTO-ACCOUNTS: POST {url} → HTTP {r.status_code}")
        if r.status_code in [200, 201]:
            return True, r.json(), ""
        return False, {}, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, {}, str(e)


def _build_reg_body(fields: dict, email: str, password: str) -> dict:
    """Build registration body from field map."""
    body = {}
    for purpose, name in fields.items():
        pl = purpose.lower()
        if "email" in pl:
            body[name] = email
        elif "confirm" in pl or "repeat" in pl:
            body[name] = password
        elif "pass" in pl:
            body[name] = password
        elif "user" in pl or "name" in pl:
            body[name] = email.split("@")[0]
        else:
            body[name] = email
    return body


def _dig(obj: dict, path: list):
    """Safely dig into a nested dict using a list of keys."""
    for key in path:
        if isinstance(obj, dict) and key in obj:
            obj = obj[key]
        else:
            return None
    return obj


def _extract_token(body: dict, r: httpx.Response) -> str:
    """Extract token from response body or headers."""
    if isinstance(body, dict):
        for f in ["token", "access_token", "accessToken", "jwt", "auth_token"]:
            if f in body and isinstance(body[f], str):
                return body[f]
        if isinstance(body.get("data"), dict):
            for f in ["token", "access_token", "accessToken"]:
                if f in body["data"]:
                    return str(body["data"][f])
        if isinstance(body.get("authentication"), dict):
            if "token" in body["authentication"]:
                return str(body["authentication"]["token"])
    auth = r.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    for name in ["token", "auth_token", "access_token"]:
        if name in r.cookies:
            return r.cookies[name]
    return ""


def _extract_userid(body: dict) -> str:
    """Extract user ID from response body."""
    if not isinstance(body, dict):
        return ""
    for f in ["id", "user_id", "userId", "uid"]:
        if f in body:
            return str(body[f])
    if isinstance(body.get("data"), dict):
        for f in ["id", "user_id", "userId"]:
            if f in body["data"]:
                return str(body["data"][f])
    if isinstance(body.get("authentication"), dict):
        if "bid" in body["authentication"]:
            return str(body["authentication"]["bid"])
    return ""


# ── Shared login (used by broken_auth.py) ────────────────────────

async def login_one_account(
    target_url: str,
    email: str,
    password: str,
) -> tuple[str, str]:
    """
    Log in with one set of credentials and return (token, user_id).
    Used by broken_auth.py to get a JWT to analyse.
    """
    async with httpx.AsyncClient(
        timeout=settings.request_timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        app_type = await _detect_app(client, target_url)

        if app_type == "juiceshop":
            login_url = target_url + "/rest/user/login"
            ok, body, err = await _post_get_response(
                client, login_url, _generic_login_body(email, password)
            )
            if ok:
                return (_dig(body, ["authentication", "token"]) or "",
                        str(_dig(body, ["authentication", "bid"]) or ""))
            return "", ""

        # Generic fallback
        token, uid, _ = await _find_and_login(
            client, target_url,
            {"url": target_url + "/api/auth/register", "fields": {}},
            email, password
        )
        return token, uid


def _needs_help(error: str, help_message: str) -> dict:
    return {
        "success": False, "token_a": "", "user_a_email": "",
        "user_a_id": "", "token_b": "", "user_b_email": "",
        "user_b_id": "", "error": error,
        "needs_help": True, "help_message": help_message,
    }
