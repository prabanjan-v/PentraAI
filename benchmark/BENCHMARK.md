# PentraAI — Benchmark Methodology & Results

This document defines how PentraAI is benchmarked, the ground-truth vulnerabilities
used as the baseline, and the results. Targets: **OWASP Juice Shop** and **OWASP
crAPI**, both run locally in Docker.

> **Note on target selection.** The original brief named DVWA. We substitute crAPI
> because PentraAI's modules target *authorization and API-layer* flaws
> (IDOR/BOLA, broken auth/JWT, SSRF, BFLA, race conditions), which crAPI exercises
> directly, whereas DVWA centres on SQL injection and XSS — classes PentraAI does
> not claim to detect. Benchmarking against crAPI + Juice Shop therefore measures
> the tool against the vulnerability classes it is actually designed to find.

---

## 1. What we measure

For each target we report:

- **Detection rate (recall)** = (unique in-scope vulns detected) ÷ (in-scope vulns present).
  This is the headline "did it find the real bugs" number.
- **Precision** = TP ÷ (TP + FP). Of everything it flagged, how much was real.
- **False-positive rate** = FP ÷ (all findings). How noisy the tool is.
- **Per-module breakdown** — the same counts split across idor / broken_auth / ssrf /
  bfla / race_condition, so strengths and gaps are visible.
- **Runtime** — wall-clock seconds per full scan.

**Scope matters.** Detection rate is computed only over *in-scope* vulnerability
classes (the five PentraAI modules). Counting DVWA/Juice-Shop SQLi or XSS against
PentraAI would be measuring it on things it never attempts, so those are excluded
from the denominator. This is stated explicitly so the number is honest and
defensible.

### Definitions

- **True Positive (TP):** a finding that corresponds to a real, in-scope vulnerability.
- **False Positive (FP):** a finding that does not correspond to a real vulnerability
  (a false alarm), OR a finding for a vuln class that isn't actually present in that target.
- **False Negative (FN):** an in-scope ground-truth vuln that PentraAI did **not** report.

---

## 2. Ground truth (baseline)

These are the documented, in-scope vulnerabilities in each target. Sources: the
official OWASP crAPI challenges page and the OWASP Juice Shop companion guide.
The machine-readable version lives in `ground_truth.json`.

### OWASP crAPI

| ID | Module | Vulnerability | Endpoint (hint) |
|---|---|---|---|
| crapi-idor-1 | idor | BOLA — read another user's vehicle location | `/identity/api/v2/vehicle/{id}/location` |
| crapi-idor-2 | idor | BOLA — read another user's mechanic reports | `/workshop/api/mechanic/mechanic_report` |
| crapi-auth-1 | broken_auth | JWT forgery (alg=none / weak secret / alg confusion) | `Authorization: Bearer` |
| crapi-ssrf-1 | ssrf | SSRF via contact-mechanic form | `/workshop/api/merchant/contact_mechanic` |
| crapi-bfla-1 | bfla | BFLA — delete another user's video via admin endpoint | `DELETE /identity/api/v2/admin/videos/{id}` |
| crapi-race-1 | race_condition | Race — redeem an already-claimed coupon *(candidate — verify)* | `/community/api/v2/coupon/validate-coupon` |

### OWASP Juice Shop

| ID | Module | Vulnerability | Endpoint (hint) |
|---|---|---|---|
| js-idor-1 | idor | IDOR — view another user's basket | `GET /rest/basket/{id}` |
| js-idor-2 | idor | IDOR — add item to another user's basket | `POST /api/BasketItems` |
| js-idor-3 | idor | IDOR — forged feedback via client `UserId` | `POST /api/Feedbacks` |
| js-auth-1 | broken_auth | JWT — unsigned / `alg=none` token accepted | `Authorization: Bearer` |
| js-auth-2 | broken_auth | JWT — forge RSA-signed token (Tier 2 / alg confusion) | `Authorization: Bearer` |
| js-ssrf-1 | ssrf | SSRF — request a hidden internal resource | profile image / order URL |

> BFLA and race-condition have no clean, in-scope instance in Juice Shop, so they
> are intentionally absent from its ground truth. If PentraAI's bfla/race modules
> fire on Juice Shop, those firings count as **false positives** — which is exactly
> what we want the benchmark to reveal.

---

## 3. How to run it (step by step)

**Prerequisites:** PentraAI installed, `.env` filled with your LLM keys,
`playwright install chromium` done, and both targets running.

1. **Start the targets.**
   - Juice Shop: `docker run --rm -p 3001:3000 bkimminich/juice-shop`
   - crAPI: follow the OWASP crAPI docker-compose (it exposes the app, typically on `:8888`).

2. **Start PentraAI.** From `backend/`: `uvicorn main:app --port 8000`

3. **Configure targets.** In this `benchmark/` folder:
   `cp targets.example.json targets.json`, then edit `targets.json`:
   - Set the correct `target_url` for each app.
   - Juice Shop: two throwaway account emails/passwords are fine (the tool can
     self-register).
   - crAPI: paste two pre-authenticated JWTs into `user_a_token` / `user_b_token`
     (crAPI requires email verification, so tokens are more reliable than auto-login).
     Grab them from DevTools → Network → any authenticated request → `Authorization`.

4. **Run the scans.**
   ```
   python benchmark.py run --all
   ```
   This scans both targets, streams findings live, times each scan, and writes
   `results/<target>_raw.json` and `results/<target>_findings.csv`.

5. **Review the findings.** Open each `results/<target>_findings.csv`. For every row,
   put `TP` or `FP` in the `verdict` column. For each `TP`, copy the matching
   ground-truth id (e.g. `js-idor-1`) into the `gt_id` column. This human-verification
   step is deliberate — auto-labelling security findings as true/false is unreliable,
   and a grader expects a human in the loop.

6. **Score it.**
   ```
   python benchmark.py score --all
   ```
   This prints and writes `results/<target>_scores.md` with detection rate,
   precision, false-positive rate, and the per-module breakdown.

7. **Paste the numbers into Section 4 below** (or just attach the generated
   `*_scores.md` files).

---

## 4. Results (fill in after running)

> Replace the `—` cells with your generated numbers. Keep one decimal / whole-percent.

### Summary

| Target | In-scope vulns | Detected | Detection rate | Precision | FP rate | Runtime |
|---|---|---|---|---|---|---|
| OWASP Juice Shop | 6 | — | — | — | — | — s |
| OWASP crAPI | 6 | — | — | — | — | — s |

### Per-module (combine both targets, or keep separate)

| Module | In-scope | Detected | TP | FP | Notes |
|---|---|---|---|---|---|
| idor | — | — | — | — | |
| broken_auth | — | — | — | — | |
| ssrf | — | — | — | — | |
| bfla | — | — | — | — | |
| race_condition | — | — | — | — | |

### Short write-up (template)

> Across the two benchmark targets, PentraAI detected **X of 12** in-scope
> vulnerabilities (detection rate **Y%**) at a precision of **Z%** and a
> false-positive rate of **W%**. It performed strongest on **\<module\>**,
> reliably confirming \<…\>. The main gaps were **\<missed ground-truth ids\>**,
> which \<reason: not probed / requires specific setup / out of current coverage\>.
> Mean scan time was **N seconds** per target.

---

## 5. Honesty notes (keep these accurate in your report)

- **In-scope framing.** Always state that detection rate is over the five module
  classes, not every vulnerability in the app. This is standard for a specialised
  scanner and protects you from a "but it missed the SQLi" objection.
- **Candidate ground-truth items** (`crapi-race-1`, `js-idor-3`) are marked as such.
  Verify they're genuinely exploitable in your build before counting them; if they
  aren't cleanly in your modules' coverage, list them as known gaps rather than
  inflating the denominator.
- **Reproducibility.** The `results/*_raw.json` files capture the full event stream
  and final report for each scan, so the run is reproducible and auditable.
