"""
modules/race_condition.py — Race Condition & Concurrency Control Testing (OWASP A06)

Two distinct vulnerability classes detected:

1. TRUE RACE CONDITION (TOCTOU — Time Of Check, Time Of Use)
   Server checks a condition THEN acts on it.
   Between check and action, many requests slip through.
   Example: check "coupon used?" → NO → 30 requests all pass before any marks it used.
   All 30 get the discount. Server processed the action 30x when it should be 1x.

2. MISSING RATE LIMITING (Concurrency Control Bypass)
   Server has no limit on how many times an action can be performed.
   30 simultaneous submissions all accepted because no counter exists.
   Example: feedback endpoint accepts unlimited submissions per user.
   Not TOCTOU, but still a valid concurrency security finding.

Strategy: PROBE THEN RACE
   Step 1: Find endpoints that respond 200 to a single request (probe)
   Step 2: Race that proven-working endpoint with 30 simultaneous requests
   Step 3: Count successes vs expected max
   Step 4: LLM determines the finding type and severity

   This avoids wasting race attempts on endpoints that don't work,
   and ensures we only report real findings.

FALSE-POSITIVE HARDENING (conservative — can only remove weak findings):
   * A finding is only reported when the endpoint represents a CONSTRAINED resource
     (coupon, order, checkout, wallet, credit, transfer, otp, ...). "Many submissions
     accepted" on an unconstrained endpoint (feedback, comments) is NOT a vulnerability
     and is reported as info only in the logs, not as a finding.
   * A TRUE race_condition requires an actual overrun (successes > expected maximum),
     so a single legitimate success can never be mislabelled as a race.
"""

import json
import asyncio
import httpx
from llm import call_llm
from config import settings
from knowledge import knowledge_section
from modules.auto_accounts import create_two_accounts, login_one_account

# Race-condition reference methodology (from skill_knowledge/race_condition.md),
# injected into the LLM verdict prompt as a modest slice.
_RACE_KB = knowledge_section("race_condition", max_chars=1500)

RACE_COUNT = 30
RACE_TIMEOUT = 45


# ── Constrained-resource gate (false-positive reduction) ──────────
# Only endpoints whose purpose implies a limit should be flagged. Accepting many
# concurrent requests is only a vulnerability when something SHOULD have stopped
# them (one coupon, one checkout of a fixed balance, one OTP, ...).
_CONSTRAINED_KEYWORDS = {
    "coupon", "voucher", "promo", "discount", "redeem", "reward", "referral",
    "checkout", "order", "orders", "place_order", "purchase", "payment", "pay",
    "transfer", "wallet", "credit", "balance", "topup", "top-up", "withdraw",
    "cashout", "otp", "claim", "gift", "bonus", "points", "stock", "inventory",
    "reserve", "booking",
}


def _is_constrained_resource(candidate: dict) -> bool:
    """True if the endpoint represents a resource that should be limited."""
    text = f"{candidate.get('url', '')} {candidate.get('name', '')}".lower()
    return any(keyword in text for keyword in _CONSTRAINED_KEYWORDS)


async def run_race_condition(
    recon_data: dict,
    target_url: str,
    user_email: str = "",
    user_password: str = "",
) -> list[dict]:
    """
    Main entry point. Probe-then-race strategy on any target.
    """
    target_url = target_url.rstrip("/")
    findings   = []

    # ── Get session ───────────────────────────────────────────────
    token, user_id = "", ""

    if user_email and user_password:
        print(f"RACE: Using provided credentials ({user_email})...")
        token, user_id = await login_one_account(target_url, user_email, user_password)
    else:
        print("RACE: Auto-creating test account...")
        accounts = await create_two_accounts(target_url, recon_data)
        if accounts["success"]:
            token   = accounts["token_a"]
            user_id = accounts["user_a_id"]
        else:
            return [{
                "vulnerability": "Race Condition — Setup Failed",
                "owasp":         "A06:2025 — Vulnerable and Outdated Components",
                "endpoint":      target_url,
                "severity":      "info",
                "needs_help":    True,
                "error":         accounts["error"],
                "help_message":  accounts["help_message"],
                "evidence":      {},
                "ai_reasoning":  accounts["error"],
            }]

    if not token:
        print("RACE: Could not get session. Skipping.")
        return []

    tech         = recon_data.get("tech_stack", {})
    is_juiceshop = tech.get("app") == "OWASP Juice Shop"

    print(f"RACE: Session ready (user_id={user_id})")

    async with httpx.AsyncClient(
        timeout          = RACE_TIMEOUT,
        follow_redirects = True,
        verify           = False,
        http2            = True,
    ) as client:

        headers = {"Authorization": f"Bearer {token}"}

        # ── Build candidate list ──────────────────────────────────
        candidates = await _build_candidates(
            client, target_url, headers, user_id,
            recon_data, is_juiceshop
        )

        print(f"RACE: Built {len(candidates)} candidate(s) to probe")

        # ── Probe then race each candidate ────────────────────────
        for candidate in candidates:
            print(f"\nRACE: Probing → {candidate['name']}")
            print(f"RACE:   URL: {candidate['url']}")

            # Step 1: Probe with ONE request to confirm endpoint works
            probe_result = await _probe(client, candidate, headers)

            if not probe_result["works"]:
                print(f"RACE:   ✗ Probe failed (HTTP {probe_result['status']}: {probe_result['body'][:60]}) — skipping")
                continue

            print(f"RACE:   ✓ Probe succeeded (HTTP {probe_result['status']}) — racing {RACE_COUNT} simultaneous requests")

            # For feedback: refresh captcha right before race
            # The probe consumed the first captcha, so get a fresh one
            if candidate.get("pre_race_fn") == "refresh_captcha":
                new_id, new_answer = await _get_captcha(
                    client, candidate.get("base", target_url), headers
                )
                if new_id is not None:
                    candidate["body"]["captchaId"] = new_id
                    candidate["body"]["captcha"]   = str(new_answer)
                    print(f"RACE:   Refreshed captcha: id={new_id}, answer={new_answer}")

            # Step 2: Race with RACE_COUNT simultaneous requests
            race_result = await _race(client, candidate, headers)

            print(f"RACE:   Results: {race_result['successes']} success, {race_result['failures']} failed, {race_result['errors']} errors")

            # Step 3: LLM determines finding type and severity
            finding = _llm_evaluate(
                candidate    = candidate,
                probe_result = probe_result,
                race_result  = race_result,
                target_url   = target_url,
            )

            if finding:
                findings.append(finding)
                print(f"RACE: ⚠️  VULNERABLE — {candidate['name']} [{finding['finding_type']}]")
            else:
                print(f"RACE: ✓ Protected — {candidate['name']}")

    return findings


# ── Build candidate list ──────────────────────────────────────────

async def _build_candidates(
    client: httpx.AsyncClient,
    base: str,
    headers: dict,
    user_id: str,
    recon_data: dict,
    is_juiceshop: bool,
) -> list[dict]:
    """
    Build a list of endpoints to probe and race.
    For Juice Shop: use known endpoints.
    For real targets: use LLM + pattern matching on recon data.
    """
    candidates = []
    bid = int(user_id) if user_id and user_id.isdigit() else 1

    if is_juiceshop:
        # ── Juice Shop candidates ─────────────────────────────────

        # Candidate 1: Feedback submission (rate limit test)
        captcha_id, captcha_answer = await _get_captcha(client, base, headers)
        if captcha_id is not None:
            # Use same captcha for both probe and race
            # The probe marks it used, but race fires immediately after
            # If server has a race window: multiple submissions accepted
            feedback_body = {
                "comment":   "PentraAI race condition test",
                "rating":    5,
                "captchaId": captcha_id,
                "captcha":   str(captcha_answer),
            }
            candidates.append({
                "name":             "Feedback submission (rate limit)",
                "url":              f"{base}/api/Feedbacks",
                "method":           "POST",
                "body":             feedback_body,
                "expected_success": 1,
                "finding_hint":     "rate_limit",
                "reset_fn":         None,
                "pre_race_fn":      "refresh_captcha",  # signal to refresh before race
                "base":             base,
                "headers":          headers,
            })

        # Candidate 2: Basket add (true race condition test)
        # Each simultaneous request tries to add the same product
        # A race condition would cause quantity to multiply
        candidates.append({
            "name":        "Basket add (quantity race)",
            "url":         f"{base}/api/BasketItems",
            "method":      "POST",
            "body":        {"ProductId": 2, "BasketId": bid, "quantity": 1},
            "expected_success": 1,
            "finding_hint":     "race_condition",
            "reset_fn":         None,
        })

        # Candidate 3: Coupon — dynamically discover working code
        coupon_url = await _find_working_juiceshop_coupon(client, base, headers, bid)
        if coupon_url:
            candidates.append({
                "name":        "Coupon redemption (TOCTOU race)",
                "url":         coupon_url,
                "method":      "GET",
                "body":        None,
                "expected_success": 1,
                "finding_hint":     "race_condition",
                "reset_fn":         None,
            })
        else:
            print("RACE: No working Juice Shop coupon found — skipping coupon test")

        # Candidate 4: Checkout race
        # Race placing an order to see if it can be placed multiple times
        checkout_url = f"{base}/rest/basket/{bid}/checkout"
        candidates.append({
            "name":        "Order checkout (duplicate order race)",
            "url":         checkout_url,
            "method":      "POST",
            "body":        {},
            "expected_success": 1,
            "finding_hint":     "race_condition",
            "reset_fn":         None,
        })

    else:
        # ── Generic target candidates ─────────────────────────────
        alive = recon_data.get("alive_endpoints", [])

        # Detect crAPI by its signature endpoints and add known race targets
        is_crapi = any("/workshop/api/" in e or "/identity/api/" in e
                       or "/community/api/" in e for e in alive)

        if is_crapi:
            print("RACE: Detected crAPI — adding known race condition targets")
            # crAPI's coupon endpoint with its known valid coupon code
            candidates.append({
                "name":             "crAPI coupon validation race",
                "url":              f"{base}/community/api/v2/coupon/validate-coupon",
                "method":           "POST",
                "body":             {"coupon_code": "TRAC075", "amount": 75},
                "expected_success": 1,
                "finding_hint":     "race_condition",
                "reset_fn":         None,
            })
            candidates.append({
                "name":             "crAPI apply coupon race",
                "url":              f"{base}/workshop/api/shop/apply_coupon",
                "method":           "POST",
                "body":             {"coupon_code": "TRAC075", "amount": 75},
                "expected_success": 1,
                "finding_hint":     "race_condition",
                "reset_fn":         None,
            })
            # crAPI order placement
            candidates.append({
                "name":             "crAPI order placement race",
                "url":              f"{base}/workshop/api/shop/orders",
                "method":           "POST",
                "body":             {"product_id": 1, "quantity": 1},
                "expected_success": 1,
                "finding_hint":     "race_condition",
                "reset_fn":         None,
            })

        # Pattern-based detection
        pattern_candidates = _pattern_candidates(alive, base)

        # LLM-based detection
        llm_candidates = _llm_candidates(alive, base)

        # Merge and deduplicate
        seen = set()
        for c in candidates + pattern_candidates + llm_candidates:
            if c["url"] not in seen:
                seen.add(c["url"])
                if c not in candidates:
                    candidates.append(c)

    return candidates[:8]


async def _find_working_juiceshop_coupon(
    client: httpx.AsyncClient,
    base: str,
    headers: dict,
    basket_id: int,
) -> str | None:
    """
    Dynamically discover a working Juice Shop coupon code.

    Strategy:
    1. Ensure basket has an item (required for coupon)
    2. Try known coupon codes in multiple formats
    3. Return the first URL that returns HTTP 200
    """
    import base64 as _b64

    # Ensure basket has an item first
    try:
        await client.post(
            f"{base}/api/BasketItems",
            json={"ProductId": 1, "BasketId": basket_id, "quantity": 1},
            headers=headers,
        )
    except Exception:
        pass

    # Known Juice Shop promotional codes (try multiple formats)
    raw_codes = [
        "WMNSDY2019", "ORANGE2019", "BLUES2019",
        "WMNSDY2020", "WMNSDY2021", "WMNSDY2022",
        "DISCOUNT10", "SAVE10", "PROMO2024", "PROMO2025",
    ]

    for code in raw_codes:
        # Standard base64
        encoded = _b64.b64encode(code.encode()).decode()
        url = f"{base}/rest/basket/{basket_id}/coupon/{encoded}"
        try:
            r = await client.get(url, headers=headers)
            print(f"RACE:   Coupon {code} → HTTP {r.status_code}: {r.text[:50]}")
            if r.status_code == 200:
                print(f"RACE:   Found working coupon: {code}")
                return url
        except Exception:
            continue

        # Without padding
        encoded_nopad = encoded.rstrip("=")
        if encoded_nopad != encoded:
            url2 = f"{base}/rest/basket/{basket_id}/coupon/{encoded_nopad}"
            try:
                r = await client.get(url2, headers=headers)
                if r.status_code == 200:
                    return url2
            except Exception:
                continue

    return None


async def _get_captcha(
    client: httpx.AsyncClient,
    base: str,
    headers: dict,
) -> tuple:
    """
    Fetch and solve Juice Shop's arithmetic captcha.
    Returns (captcha_id, answer) or (None, None).
    """
    try:
        r = await client.get(f"{base}/rest/captcha/", headers=headers)
        if r.status_code != 200:
            return None, None

        data = r.json()
        captcha_id = data.get("captchaId")

        if captcha_id is None:
            return None, None

        # Use server's pre-computed answer if available
        server_answer = data.get("answer")
        if server_answer is not None:
            print(f"RACE:   Captcha: id={captcha_id}, answer={server_answer} (from server)")
            return captcha_id, server_answer

        # Solve arithmetic ourselves
        captcha_q = data.get("captcha", "")
        if not captcha_q:
            return None, None

        import re as _re
        safe_expr = _re.sub(r"[^0-9+\-*/\s()]", "", captcha_q)
        answer = int(eval(safe_expr))
        print(f"RACE:   Captcha: id={captcha_id}, q='{captcha_q}', answer={answer}")
        return captcha_id, answer

    except Exception as e:
        print(f"RACE:   Captcha fetch error: {e}")
        return None, None


def _pattern_candidates(alive: list[str], base: str) -> list[dict]:
    """
    Find race condition candidates by URL pattern matching.
    Works on ANY target — looks for action-type endpoints by keyword.
    Covers crAPI-style microservice paths and standard REST APIs.
    """
    candidates = []
    patterns = {
        "coupon":        ("Coupon redemption race",   "POST", {"coupon_code": "TRAC075"}),
        "apply_coupon":  ("Apply coupon race",        "POST", {"coupon_code": "TRAC075"}),
        "voucher":       ("Voucher redemption race",  "POST", {"code": "TEST123"}),
        "promo":         ("Promo code race",          "POST", {"promo": "SAVE10"}),
        "redeem":        ("Redemption race",          "POST", {"token": "TEST"}),
        "referral":      ("Referral bonus race",      "POST", {}),
        "reward":        ("Reward claiming race",     "POST", {}),
        "transfer":      ("Transfer race",            "POST", {"amount": 1}),
        "discount":      ("Discount race",            "POST", {"code": "DISC10"}),
        "otp":           ("OTP verification race",   "POST", {"otp": "123456"}),
        "claim":         ("Claim race",               "POST", {}),
        "checkout":      ("Checkout race",            "POST", {}),
        "place_order":   ("Place order race",         "POST", {}),
        "wallet":        ("Wallet credit race",       "POST", {"amount": 100}),
        "credit":        ("Credit race",              "POST", {"amount": 100}),
    }

    for endpoint in alive:
        lower = endpoint.lower()
        for keyword, (name, method, body) in patterns.items():
            if keyword in lower:
                url = endpoint if endpoint.startswith("http") else (
                    base.rstrip("/") + "/" + endpoint.lstrip("/")
                )
                candidates.append({
                    "name":             name,
                    "url":              url,
                    "method":           method,
                    "body":             body,
                    "expected_success": 1,
                    "finding_hint":     "race_condition",
                    "reset_fn":         None,
                })
                break

    return candidates[:4]


def _llm_candidates(alive: list[str], base: str) -> list[dict]:
    """Ask LLM to identify race condition targets from discovered endpoints."""
    prompt = f"""You are a penetration tester identifying race condition targets.

Target: {base}
Discovered endpoints: {alive[:40]}

Which endpoints could have race conditions or missing rate limits?
Focus on: coupon/voucher redemption, referral bonuses, OTP verification,
transfers, rewards, rate-limited actions, one-time use codes.

Return ONLY a JSON array (max 3 items). Use FULL URLs starting with {base}.
Return [] if nothing suitable found.

[
  {{
    "name": "Coupon redemption",
    "url": "{base}/api/coupons/apply",
    "method": "POST",
    "body": {{"code": "TEST10"}},
    "expected_success": 1,
    "finding_hint": "race_condition"
  }}
]"""

    try:
        raw = call_llm(prompt, expect_json=True)
        candidates = json.loads(raw)
        if not isinstance(candidates, list):
            return []

        # Validate/fix URLs — skip any item that is not a dict
        valid = []
        for c in candidates:
            if not isinstance(c, dict):
                continue   # LLM sometimes returns strings — skip them
            url = c.get("url", "")
            if not url:
                continue
            if not url.startswith("http"):
                url = base.rstrip("/") + "/" + url.lstrip("/")
                c["url"] = url
            if "finding_hint" not in c:
                c["finding_hint"] = "race_condition"
            if "method" not in c:
                c["method"] = "POST"
            if "expected_success" not in c:
                c["expected_success"] = 1
            valid.append(c)
        return valid

    except Exception as e:
        print(f"RACE: LLM candidate error: {e}")
        return []


# ── Probe ────────────────────────────────────────────────────────

async def _probe(
    client: httpx.AsyncClient,
    candidate: dict,
    headers: dict,
) -> dict:
    """
    Send ONE request to confirm the endpoint works.
    Returns result dict with works, status, body.
    """
    url    = candidate["url"]
    method = candidate.get("method", "POST").upper()
    body   = candidate.get("body")

    try:
        if method == "GET":
            r = await client.get(url, headers=headers)
        else:
            r = await client.request(method, url, json=body, headers=headers)

        works = r.status_code in [200, 201]
        return {
            "works":  works,
            "status": r.status_code,
            "body":   r.text[:300],
        }

    except Exception as e:
        return {"works": False, "status": 0, "body": str(e)}


# ── Race ─────────────────────────────────────────────────────────

async def _race(
    client: httpx.AsyncClient,
    candidate: dict,
    headers: dict,
) -> dict:
    """
    Fire RACE_COUNT simultaneous requests.
    Returns success/failure/error counts and sample responses.
    """
    url    = candidate["url"]
    method = candidate.get("method", "POST").upper()
    body   = candidate.get("body")

    async def one_request():
        try:
            if method == "GET":
                return await client.get(url, headers=headers)
            return await client.request(method, url, json=body, headers=headers)
        except Exception as e:
            return e

    responses = await asyncio.gather(
        *[one_request() for _ in range(RACE_COUNT)],
        return_exceptions=True,
    )

    successes = [r for r in responses if not isinstance(r, Exception) and r.status_code in [200, 201]]
    failures  = [r for r in responses if not isinstance(r, Exception) and r.status_code not in [200, 201]]
    errors    = [r for r in responses if isinstance(r, Exception)]

    return {
        "successes":      len(successes),
        "failures":       len(failures),
        "errors":         len(errors),
        "sample_success": [r.text[:200] for r in successes[:3]],
        "sample_failure": [r.text[:100] for r in failures[:2]],
    }


# ── LLM evaluation ───────────────────────────────────────────────

def _llm_evaluate(
    candidate: dict,
    probe_result: dict,
    race_result: dict,
    target_url: str,
) -> dict | None:
    """
    Ask the LLM to determine:
    1. Is there a vulnerability?
    2. Is it a true TOCTOU race condition or missing rate limiting?
    3. What is the severity?

    Returns a finding dict or None.
    """
    expected  = candidate.get("expected_success", 1)
    successes = race_result["successes"]

    # If zero requests succeeded in the race → server is protected
    # Never flag as vulnerable when nothing got through
    if successes == 0:
        return None
    hint = candidate.get("finding_hint", "race_condition")

    prompt = f"""You are a security analyst evaluating a race condition test result.

=== Race condition / concurrency reference ===
{_RACE_KB}
=== end reference ===

Endpoint tested: {candidate['url']}
Method: {candidate.get('method', 'POST')}
Test description: {candidate['name']}

Probe result (1 request):
- HTTP {probe_result['status']}: {probe_result['body'][:100]}

Race result ({RACE_COUNT} simultaneous requests):
- Succeeded (HTTP 200/201): {successes}
- Failed: {race_result['failures']}
- Errors: {race_result['errors']}
- Expected maximum successes if protected: {expected}

Sample successful responses:
{json.dumps(race_result['sample_success'], indent=2)}

Sample failed responses:
{json.dumps(race_result['sample_failure'], indent=2)}

Determine:
1. Is this a vulnerability? (more successes than expected, or suspicious behavior)
2. What TYPE of vulnerability is it?
   - "race_condition": TOCTOU — action that should happen once happened multiple times due to timing
   - "missing_rate_limit": No rate limiting — server accepts unlimited concurrent submissions
   - "none": Server properly handled concurrency
3. Severity?

Return ONLY JSON:
{{
  "vulnerable": true or false,
  "finding_type": "race_condition" or "missing_rate_limit" or "none",
  "severity": "high" or "medium" or "low",
  "reasoning": "one sentence describing exactly what happened"
}}"""

    try:
        raw = call_llm(prompt, expect_json=True)
        result = json.loads(raw)
    except Exception:
        # Simple fallback
        if successes > expected * 2:
            result = {
                "vulnerable":   True,
                "finding_type": hint,
                "severity":     "high",
                "reasoning":    f"{successes}/{RACE_COUNT} simultaneous requests succeeded (expected max {expected})"
            }
        else:
            return None

    if not result.get("vulnerable"):
        return None

    finding_type = result.get("finding_type", hint)

    # ── Deterministic false-positive guards (added) ───────────────────────────
    # Guard A — control held: if any concurrent request was REJECTED with a
    # message showing the protection triggered (insufficient balance, already
    # used, duplicate, limit reached, out of stock, conflict...), then the
    # resource control actually held and this is not a confirmed race win.
    _PROTECTION_SIGNALS = (
        "insufficient", "not enough", "already", "duplicate", "limit",
        "exceeded", "denied", "forbidden", "out of stock", "sold out",
        "conflict", "expired", "invalid coupon", "not allowed",
    )
    _failure_text = " ".join(str(x).lower() for x in race_result.get("sample_failure", []))
    if race_result.get("failures", 0) > 0 and any(s in _failure_text for s in _PROTECTION_SIGNALS):
        print(f"RACE:   (info) {race_result.get('failures')} request(s) rejected by the resource "
              f"control ('{_failure_text[:60]}...') — control held, not a confirmed race")
        return None

    # Guard B — creation endpoint: creating many INDEPENDENT resources
    # (new-coupon, signup, register, /new, create) is not a TOCTOU overrun of a
    # single limited resource. Downgrade to informational rather than a race.
    _url_l = candidate.get("url", "").lower()
    _CREATE_MARKERS = ("new-", "/new", "create", "signup", "sign-up", "register",
                       "checkout", "/order", "purchase", "place-order", "/buy")
    if finding_type == "race_condition" and any(m in _url_l for m in _CREATE_MARKERS):
        print(f"RACE:   (info) {successes}/{RACE_COUNT} succeeded on a creation endpoint "
              f"'{candidate['name']}' — many independent creates is not a TOCTOU race; not reported")
        return None
    # ──────────────────────────────────────────────────────────────────────────

    # ── Conservative false-positive gate (only removes weak findings) ──
    # 1) Only report on resources that SHOULD be limited. Accepting many concurrent
    #    requests on an unconstrained endpoint (feedback, comments, generic POST) is
    #    normal behaviour, not a vulnerability.
    if not _is_constrained_resource(candidate):
        print(f"RACE:   (info) {successes}/{RACE_COUNT} succeeded on an unconstrained "
              f"endpoint '{candidate['name']}' — not reported (no limit is expected here)")
        return None

    # 2) A TRUE race/TOCTOU requires an actual overrun beyond the allowed maximum.
    #    A single legitimate success must never be labelled a race condition.
    if finding_type == "race_condition" and successes <= expected:
        print(f"RACE:   (info) {successes}/{RACE_COUNT} succeeded but no overrun beyond "
              f"expected max {expected} — not a race condition")
        return None

    # Build human-readable vulnerability name
    if finding_type == "race_condition":
        vuln_name = f"Race Condition (TOCTOU) — {candidate['name']}"
        owasp     = "A06:2025 — Vulnerable and Outdated Components"
    elif finding_type == "missing_rate_limit":
        vuln_name = f"Missing Rate Limiting — {candidate['name']}"
        owasp     = "A06:2025 — Vulnerable and Outdated Components"
    else:
        return None

    return {
        "vulnerability": vuln_name,
        "owasp":         owasp,
        "endpoint":      candidate["url"],
        "severity":      result.get("severity", "medium"),
        "finding_type":  finding_type,
        "needs_help":    False,
        "evidence": {
            "attack":                   "race_condition_probe_then_race",
            "description":              candidate["name"],
            "probe_status":             probe_result["status"],
            "probe_response":           probe_result["body"][:100],
            "requests_sent":            RACE_COUNT,
            "successful_responses":     successes,
            "failed_responses":         race_result["failures"],
            "expected_max_successes":   expected,
            "sample_success_responses": race_result["sample_success"],
            "sample_failure_responses": race_result["sample_failure"],
        },
        "ai_reasoning": result.get("reasoning", ""),
    }