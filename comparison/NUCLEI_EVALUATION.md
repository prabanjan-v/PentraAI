# Comparative Evaluation: PentraAI vs Nuclei

## 1. Purpose

This document satisfies the required comparative evaluation of PentraAI against
an established scanning tool, per the project brief. We selected **Nuclei**
(ProjectDiscovery) as the comparison tool and ran it against the same two
benchmark targets used to evaluate PentraAI — **OWASP crAPI** and **OWASP Juice
Shop** — under matched conditions, so the two tools' results are directly
comparable.

## 2. Why Nuclei

Nuclei is one of the most widely adopted open-source vulnerability scanners in
industry and bug-bounty practice. It is template-based: thousands of
community-maintained YAML rules describe known CVEs, exposed panels,
misconfigurations, default credentials, and technology fingerprints, and Nuclei
fires the corresponding HTTP requests and pattern-matches the responses. It
represents the class of tool PentraAI is positioned against — a fast, generic,
signature-driven scanner — which makes it the right comparison point for
demonstrating what an authenticated, reasoning-based tool adds on top.

## 3. Methodology

**Setup.** Both targets were run locally in Docker, identical to the main
PentraAI benchmark (`BENCHMARK.md`). Nuclei v3.11.0 was installed natively
(Windows binary) with the official template set (v10.4.5, 7,699 templates).

**Scan configuration.** Both targets were scanned with the same tag set and
severity range, so neither target received a more thorough or more lenient
pass than the other:

```
-tags cve,exposure,misconfig,default-login,tech,vuln
-exclude-tags dos,fuzz,intrusive
-severity info,low,medium,high,critical
```

`dos`, `fuzz`, and `intrusive` templates were excluded because these targets
are shared lab environments, not disposable infrastructure — the same caution
applied throughout the main PentraAI benchmark.

**Scoring.** Nuclei's JSON-export output was parsed and each finding was
classified as either (a) inside PentraAI's five target vulnerability classes
(IDOR/BOLA, broken authentication, SSRF, BFLA, race condition) or (b) outside
that scope (generic CVE, exposure, misconfiguration, or technology
fingerprint). PentraAI's side of the comparison uses the same confirmed
true-positive findings reported in `BENCHMARK.md`, each individually verified
against its raw request/response evidence before being counted.

## 4. Results

| Target | Nuclei findings | Nuclei findings in PentraAI's scope | PentraAI confirmed true positives |
|---|---|---|---|
| crAPI | 15 | 0 | 6 |
| Juice Shop | 16 | 0 | 3 |
| **Combined** | **31** | **0** | **9** |

**Zero of Nuclei's 31 findings overlapped with any of PentraAI's 9 confirmed
vulnerabilities, on either target.**

### 4.1 What Nuclei found

Across both targets, Nuclei's findings were exclusively infrastructure- and
fingerprint-level: missing security headers (8 instances per target),
technology detection (FingerprintHub, OpenResty), exposed developer/monitoring
endpoints (Swagger API, Prometheus metrics), and standard file presence checks
(`robots.txt`, `security.txt`). Every one of these is detectable from a single,
unauthenticated HTTP request pattern-matched against a static rule — exactly
the kind of check a template engine is built for.

### 4.2 What PentraAI found

PentraAI's 9 confirmed findings, by contrast, each required either two
authenticated sessions compared against each other, a forged cryptographic
token, or a payload injected into an application-specific business parameter:

| Vulnerability class | crAPI | Juice Shop |
|---|---|---|
| IDOR / BOLA | 2 (vehicle location, mechanic report) | 1 (basket manipulation via HTTP Parameter Pollution) |
| Broken authentication (JWT) | 2 (alg=none, algorithm confusion) | 1 (alg=none) |
| SSRF | 1 (contact-mechanic parameter injection) | 0 |
| BFLA | 1 (admin user-list endpoint) | 1 (admin user-list endpoint) |

None of these is expressible as a static request/response template: each
depends on comparing what *this specific authenticated user* should versus
did receive, or on dynamically constructing and signing a forged credential.

## 5. Interpretation

The zero-overlap result is not a weakness in either tool — it is the expected
and, in fact, the intended outcome. Nuclei and PentraAI are built to answer
different questions:

- **Nuclei answers:** "Does this application expose any of the thousands of
  known, previously-catalogued weaknesses the security community has already
  written a signature for?"
- **PentraAI answers:** "Given this application's actual authentication and
  authorization model, can one authenticated user improperly access another
  user's data or functions, or can protocol-level trust (JWT signatures) be
  broken?"

A signature-based scanner cannot express the second class of question, because
there is no fixed request/response pattern to match against — the vulnerability
only exists in the *relationship* between two sessions, or in the *semantics*
of a forged token, which requires reasoning rather than pattern matching. This
is precisely the gap PentraAI is designed to close, and this evaluation
provides direct, reproducible evidence that it does so: on the same two
targets, in the same time frame, PentraAI surfaced 9 authenticated
business-logic and access-control vulnerabilities that a leading generic
scanner, executing nearly 7,700 signature checks, did not detect a single one
of.

## 6. Reproducing this evaluation

See `NUCLEI_COMPARISON.md` for exact install and run instructions, and
`compare_nuclei.py` for the scoring script. Raw Nuclei output is in
`results/{target}_nuclei.json`; PentraAI's underlying evidence is in the main
benchmark's `results/{target}_raw.json`.