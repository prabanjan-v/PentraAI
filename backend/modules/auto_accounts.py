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
import asyncio
import httpx
from bs4 import BeautifulSoup
from llm import call_llm
from config import settings


# ── Per-scan account cache ────────────────────────────────────────
# Every module (idor, broken_auth, bfla, ssrf, race) used to register and log in
# its own fresh accounts, so one scan ran the whole register→login dance ~5 times
# — 5× the chances for an intermittent failure ("Setup Failed"). We now create the
# accounts once per target and reuse them for the rest of the scan. main.py calls
# reset_account_cache() at the start of every scan so each scan still gets fresh
# accounts.
_ACCOUNT_CACHE: dict = {}


def reset_account_cache() -> None:
    """Clear cached accounts. Called by main.py at the start of each scan."""
    _ACCOUNT_CACHE.clear()


TEST_PASSWORD = "PentraAI_Test@123"


def _make_email(suffix: str) -> str:
    short = uuid.uuid4().hex[:6]
    return f"pentraai_{suffix}_{short}@test.com"


# ── App fingerprinting ────────────────────────────────────────────

async def _detect_app(client: httpx.AsyncClient, base_url: str) -> str:
    """Detect which known app we are targeting."""
    # Retry a few times: under load the homepage GET can fail or return an
    # incomplete body, which used to drop us into the unreliable generic flow
    # (the "No login endpoint responded with a token" error).
    for attempt in range(3):
        try:
            r = await client.get(base_url)
            body = r.text.lower()
            if "juice" in body or "owasp juice" in body:
                return "juiceshop"
            if "dvwa" in body or "damn vulnerable" in body:
                return "dvwa"
            if "crapi" in body or "completely ridiculous" in body:
                return "crapi"
        except Exception:
            pass

        # crAPI's frontend may not have the name on the homepage —
        # probe its signature API endpoint to detect it
        try:
            r = await client.get(base_url + "/identity/api/auth/signup")
            # crAPI returns 405 Method Not Allowed for GET on signup (POST only)
            if r.status_code in [405, 400, 401]:
                return "crapi"
        except Exception:
            pass

        # Juice Shop signature probe as a fallback (its REST login endpoint exists)
        try:
            r = await client.get(base_url + "/rest/admin/application-version")
            if r.status_code == 200:
                return "juiceshop"
        except Exception:
            pass

        await asyncio.sleep(0.5 * (attempt + 1))

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

    If recon_data contains provided_token_a and provided_token_b
    (injected by main.py when user provides tokens directly),
    skip auto-registration and use those tokens directly.
    This supports apps with email verification like crAPI.
    """
    # ── Use provided tokens if available ─────────────────────────
    token_a = recon_data.get("provided_token_a", "")
    token_b = recon_data.get("provided_token_b", "")
    email_a = recon_data.get("provided_email_a", "user_a@pentraai.com")
    email_b = recon_data.get("provided_email_b", "user_b@pentraai.com")

    if token_a and token_b:
        print(f"AUTO-ACCOUNTS: Using provided tokens for {email_a} and {email_b}")
        return {
            "success":      True,
            "token_a":      token_a,
            "user_a_email": email_a,
            "user_a_id":    "",
            "token_b":      token_b,
            "user_b_email": email_b,
            "user_b_id":    "",
            "error":        None,
            "needs_help":   False,
            "help_message": None,
        }

    # ── Use provided credentials to login (fresh tokens each scan) ─
    # If user gave emails+passwords (not tokens), login to get fresh tokens.
    # This avoids token expiry — works for crAPI and generic JSON APIs.
    cred_email_a = recon_data.get("cred_email_a", "")
    cred_pass_a  = recon_data.get("cred_pass_a", "")
    cred_email_b = recon_data.get("cred_email_b", "")
    cred_pass_b  = recon_data.get("cred_pass_b", "")

    if cred_email_a and cred_pass_a and cred_email_b and cred_pass_b:
        print(f"AUTO-ACCOUNTS: Logging in with provided credentials (fresh tokens)...")
        tok_a, uid_a = await login_one_account(target_url, cred_email_a, cred_pass_a)
        tok_b, uid_b = await login_one_account(target_url, cred_email_b, cred_pass_b)
        if tok_a and tok_b:
            print(f"AUTO-ACCOUNTS: Both logins successful — got fresh tokens")
            return {
                "success":      True,
                "token_a":      tok_a,
                "user_a_email": cred_email_a,
                "user_a_id":    uid_a,
                "token_b":      tok_b,
                "user_b_email": cred_email_b,
                "user_b_id":    uid_b,
                "error":        None,
                "needs_help":   False,
                "help_message": None,
            }
        print(f"AUTO-ACCOUNTS: Credential login failed (A={bool(tok_a)}, B={bool(tok_b)})")

    # ── Reuse accounts already created earlier in THIS scan ───────
    _cache_key = target_url.rstrip("/")
    _cached = _ACCOUNT_CACHE.get(_cache_key)
    if _cached and _cached.get("success"):
        print("AUTO-ACCOUNTS: reusing shared accounts created earlier this scan")
        return _cached

    # ── Auto-registration flow ────────────────────────────────────
    async with httpx.AsyncClient(
        timeout=settings.request_timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        app_type = await _detect_app(client, target_url)
        print(f"AUTO-ACCOUNTS: Detected app → {app_type}")

        if app_type == "juiceshop":
            result = await _juiceshop_flow(client, target_url)
        elif app_type == "crapi":
            result = await _crapi_flow(client, target_url)
        else:
            result = await _generic_flow(client, target_url, recon_data)

    # Cache only successful setups so a transient failure doesn't poison the
    # cache — the next module will simply try again from scratch.
    if isinstance(result, dict) and result.get("success"):
        _ACCOUNT_CACHE[_cache_key] = result
    return result


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
        # Retry: the login can transiently fail right after registration.
        r_ok, r_body, err, token = False, {}, "", None
        for attempt in range(3):
            r_ok, r_body, err = await _post_get_response(client, login_url, body)
            if r_ok:
                token = _dig(r_body, ["authentication", "token"])
                if token:
                    break
            await asyncio.sleep(0.6 * (attempt + 1))
        if not r_ok:
            return _needs_help(
                error=f"Juice Shop login failed: {err}",
                help_message=(
                    f"Accounts created but login failed. "
                    f"Reason: {err}. "
                    f"Emails: {email_a}, {email_b}. Password: {TEST_PASSWORD}"
                )
            )
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


# ── crAPI flow ────────────────────────────────────────────────────

def _make_crapi_phone() -> str:
    """Generate a random 10-digit phone number not starting with 0."""
    import random
    first = str(random.randint(1, 9))            # 1-9, never 0
    rest  = "".join(str(random.randint(0, 9)) for _ in range(9))
    return first + rest


async def _crapi_flow(client: httpx.AsyncClient, base_url: str) -> dict:
    """
    Fully automated crAPI account creation.

    crAPI registration (no email verification needed):
      POST /identity/api/auth/signup
      Body: {name, email, number, password}

    crAPI login:
      POST /identity/api/auth/login
      Body: {email, password}
      Returns: {token: "eyJ..."}

    Creates two fresh accounts each scan → both get full credit,
    so stateful vulnerabilities (race conditions) are reproducible.
    """
    signup_url = base_url + "/identity/api/auth/signup"
    login_url  = base_url + "/identity/api/auth/login"

    # Generate unique emails for fresh accounts each scan
    import time, random
    stamp   = f"{int(time.time())}{random.randint(100, 999)}"
    email_a = f"pentraai_a_{stamp}@test.com"
    email_b = f"pentraai_b_{stamp}@test.com"
    password = "PentraAI@123"

    results = {}
    for label, email in [("a", email_a), ("b", email_b)]:
        # Step 1 — Register
        print(f"AUTO-ACCOUNTS: Registering crAPI User {label.upper()} ({email})...")
        signup_body = {
            "name":     f"PentraAI User {label.upper()}",
            "email":    email,
            "number":   _make_crapi_phone(),
            "password": password,
        }
        try:
            r = await client.post(signup_url, json=signup_body)
            print(f"AUTO-ACCOUNTS: Signup {label.upper()} → HTTP {r.status_code}")
            if r.status_code not in [200, 201]:
                # Account may already exist — try logging in anyway
                print(f"AUTO-ACCOUNTS: Signup returned {r.status_code}: {r.text[:100]}")
        except Exception as e:
            return _needs_help(
                error=f"crAPI signup failed for User {label.upper()}: {e}",
                help_message=f"Could not register crAPI account. Reason: {e}"
            )

        # Step 2 — Login to get token
        print(f"AUTO-ACCOUNTS: Logging in crAPI User {label.upper()}...")
        try:
            r = await client.post(login_url, json={"email": email, "password": password})
            if r.status_code == 200:
                token = r.json().get("token", "")
                if token:
                    results[label] = {"token": token, "user_id": "", "email": email}
                    print(f"AUTO-ACCOUNTS: User {label.upper()} login success ✓")
                    continue
            return _needs_help(
                error=f"crAPI login failed for User {label.upper()}: HTTP {r.status_code}",
                help_message=f"Registered but login failed. Reason: {r.text[:150]}"
            )
        except Exception as e:
            return _needs_help(
                error=f"crAPI login error for User {label.upper()}: {e}",
                help_message=f"Login request failed. Reason: {e}"
            )

    print("AUTO-ACCOUNTS: Both crAPI accounts ready ✓")
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
    Supports Juice Shop, crAPI, and generic JSON login APIs.
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

        # crAPI login — JSON API at /identity/api/auth/login
        crapi_token, crapi_uid = await _crapi_login(client, target_url, email, password)
        if crapi_token:
            return crapi_token, crapi_uid

        # Generic fallback
        token, uid, _ = await _find_and_login(
            client, target_url,
            {"url": target_url + "/api/auth/register", "fields": {}},
            email, password
        )
        return token, uid


async def _crapi_login(
    client: httpx.AsyncClient,
    target_url: str,
    email: str,
    password: str,
) -> tuple[str, str]:
    """
    Log into crAPI and return (token, user_id).
    crAPI login: POST /identity/api/auth/login {email, password}
    Returns {"token": "eyJ..."}
    """
    login_url = target_url + "/identity/api/auth/login"
    try:
        r = await client.post(login_url, json={"email": email, "password": password})
        if r.status_code == 200:
            body  = r.json()
            token = body.get("token", "")
            if token:
                print(f"AUTO-ACCOUNTS: crAPI login success for {email}")
                return token, ""
        print(f"AUTO-ACCOUNTS: crAPI login returned HTTP {r.status_code}")
    except Exception as e:
        print(f"AUTO-ACCOUNTS: crAPI login error: {e}")
    return "", ""


def _needs_help(error: str, help_message: str) -> dict:
    return {
        "success": False, "token_a": "", "user_a_email": "",
        "user_a_id": "", "token_b": "", "user_b_email": "",
        "user_b_id": "", "error": error,
        "needs_help": True, "help_message": help_message,
    }