## 2.15 RACE CONDITION DETECTION & EXPLOITATION

**═══ RACE CONDITIONS — COMPLETE DETECTION & EXPLOITATION ═══**

CWE: CWE-362 (Concurrent Execution / Race Condition) | CWE-367 (TOCTOU) | CWE-366
CVSS: 5.3–9.1 (financial loss / auth bypass / limit overrun)
OWASP: A04:2025 Insecure Design | maps to Business Logic (§2.25)
Primary references: PortSwigger "Smashing the State Machine" (2023, single-packet attack),
Turbo Intruder docs, USENIX/IEEE concurrency literature

### Overview

A race condition exists when the security of an operation depends on the *order* or
*atomicity* of steps that the server does not actually serialise. The classic shape is
Time-Of-Check to Time-Of-Use (TOCTOU): the application checks a condition (balance ≥ price,
coupon unused, requests < limit) and then acts on it, but two or more requests interleave so
that several actions all pass the same single check. The window is usually microseconds, so
the whole discipline is about landing requests inside that window simultaneously.

The single most important modern technique is the **single-packet attack**: by withholding
the final byte of many HTTP/2 requests and then releasing all final frames together, an
attacker neutralises network jitter and delivers 20–30 requests to the server within ~1 ms,
making previously "unwinnable" races reliably exploitable. On HTTP/1.1 the equivalent is the
**last-byte-sync** technique (send all requests, hold the last byte of each, release together).

Attack surface — look for any endpoint where a limited resource, a one-time action, or a
check-then-write pattern exists: redeem coupon / gift card, apply discount, withdraw /
transfer funds, "claim" or "vote" once, follow / like, MFA or OTP submission, password reset
token consumption, invite/seat allocation, rate-limit or anti-brute-force counters,
file upload check-then-move, and account-creation uniqueness checks.

### 2.15.1 Detection Methodology

#### A. Identify candidate endpoints (the "collision" heuristic)

Flag any request whose effect is *bounded* by server state read moments earlier. Signals:
a balance/quota shown in the response, a "already used" / "limit reached" error on the second
attempt, a resource that should be strictly single-use, or any state transition (`pending →
approved`, `unused → used`). If doing the action twice *sequentially* is correctly blocked,
it's a prime candidate for a concurrent bypass.

#### B. Baseline vs concurrent comparison

```
# 1. Sequential control: send the action twice in series → expect the 2nd to be rejected.
# 2. Concurrent test: send N identical requests in parallel and diff the outcomes.
#    If >1 succeeds where only 1 should → race confirmed.
```

#### C. Single-packet attack with Turbo Intruder (HTTP/2 — preferred)

```python
# Burp > Extensions > Turbo Intruder. Send the target request to it, use this script.
# %s marks where the fuzzed value goes (or send identical requests for a pure race).
def queueRequests(target, wordlists):
    # 'engine=Engine.BURP2' + concurrentConnections=1 enables the single-packet attack
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    for i in range(30):                      # 20–30 requests is the sweet spot
        engine.queue(target.req, gate='race1')   # withhold final frame, tag a gate
    engine.openGate('race1')                 # release all final frames simultaneously

def handleResponse(req, interesting):
    table.add(req)                           # inspect status/length for >1 success
```

#### D. HTTP/1.1 last-byte-sync (fallback when H2 unavailable)

```
# Turbo Intruder: concurrentConnections=30, no BURP2 engine; queue all, then openGate.
# Or curl parallel burst (crude, jitter-prone — only for coarse windows):
seq 30 | xargs -P30 -I{} curl -s -X POST https://target/redeem \
  -H "Cookie: session=..." -d 'code=ONE_TIME_CODE' -o /dev/null -w "%{http_code}\n" | sort | uniq -c
```

### 2.15.2 Exploitation Patterns

#### P1 — Limit-overrun (single check, many uses) [see §2.138]
One coupon/gift card/withdrawal is validated against one balance read, then applied N times.
- Gift-card / coupon: redeem the same one-time code 30× concurrently → credited 30×.
- Withdrawal / transfer: N parallel withdrawals each pass the "balance ≥ amount" check on the
  pre-debit balance → overdraw. **P1 financial impact.**
- "Claim once" / vote / rating: exceed the intended single action.

#### P2 — Multi-endpoint / multi-step races [see §2.139]
Two *different* endpoints operate on shared state without a lock.
- Add-to-cart at old price ‖ price update; confirm-order ‖ apply-discount.
- 2FA/OTP: submit the code to the verify endpoint while a second request advances the session
  → authentication state confusion.

#### P3 — Account / uniqueness races
- Register the same username/email in parallel → duplicate or merged accounts (relates to
  account pre-hijacking, §2.135).
- Concurrent password-reset consumption → token reused across sessions.

#### P4 — Rate-limit & anti-automation bypass
Fire the brute-force/OTP guesses concurrently so all read the pre-increment counter → the
"max N attempts" control is defeated; effective attempts ≫ N per window.

#### P5 — TOCTOU on files & objects [see §2.48]
Upload passes a validation check (extension/content), then the file is moved/processed; swap
the file contents in the window between check and use → malicious file executed.

### 2.15.3 Confirmation & Evidence
A clean PoC shows: (a) the sequential control being correctly rejected, then (b) the
concurrent burst where the success count exceeds the intended limit, with the resulting state
change (balance delta, N redemptions, duplicate record). Keep impact minimal — demonstrate
2–3 successes, not thousands (see Phase 0 PoC ethics). Note the window is timing-dependent:
report the number of attempts and observed success rate.

### 2.15.4 Real-World CVEs / Cases (detection patterns)
- HackerOne financial-race disclosures (double-spend on withdrawal/transfer) — the canonical
  bug-bounty pattern.
- **CVE-2023-connection-era** state-machine races surfaced by PortSwigger's single-packet
  research across multiple vendors.
- Coupon/gift-card multi-redeem across major e-commerce platforms (recurring class).
Pattern to flag: any monetary or one-time action where the second sequential attempt is
blocked but atomicity is not enforced at the datastore.

### 2.15.5 Tooling
Burp **Turbo Intruder** (single-packet + gate primitives — primary), Burp Repeater
"send group in parallel (single-packet)" (built-in since 2023), `h2load`/custom HTTP/2
clients for scripted bursts, `sqlmap`-style is *not* applicable. `curl -P` parallel only for
coarse windows.

### 2.15.6 Remediation & Verification
Fix at the datastore, not the app tier: use atomic operations (`UPDATE ... WHERE balance >=
amount` in a single statement, `SELECT ... FOR UPDATE`, DB unique constraints, atomic
`DECR`/compare-and-swap), idempotency keys for one-time actions, pessimistic/optimistic
locking, and serialise limited-resource mutations. Do **not** rely on a read-then-write in
application code, and do not rely on rate limiting to prevent races.

Verification re-tests (must all hold):
1. 30× concurrent single-packet redeem of a one-time code → exactly 1 success.
2. Parallel withdrawals summing above balance → total debited ≤ balance.
3. Concurrent OTP submissions → attempt counter increments per request, lockout enforced.
4. Parallel duplicate registration → exactly one account.

### 2.15.7 Decision Tree — Race Conditions

```
Endpoint mutates limited/one-time/shared state?
 └─ Does a 2nd SEQUENTIAL attempt get correctly rejected?
     ├─ NO  → not a race (it's a plain missing-check bug) → test as logic flaw (§2.25)
     └─ YES → send N concurrent (single-packet HTTP/2 via Turbo Intruder)
              ├─ >1 success? ── YES → classify impact:
              │                        ├─ money/credits → P1 financial → REPORT (§2.138)
              │                        ├─ auth/OTP/limit bypass → P1/P2 → REPORT
              │                        └─ duplicate/claim → P2/P3 → REPORT
              │                       └ NO ↓
              ├─ Try HTTP/1.1 last-byte-sync + more requests (widen the window)
              │        └─ >1 success? → YES → REPORT   └ NO ↓
              └─ Try MULTI-endpoint variant (two endpoints, shared state, §2.139)
                       └─ inconsistency? → YES → REPORT
                                          └ NO → serialised correctly; document negative
```