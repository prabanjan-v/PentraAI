# PentraAI vs Nuclei — Comparative Evaluation

This document benchmarks PentraAI against **Nuclei** (ProjectDiscovery), a fast
template-based vulnerability scanner, on the same two targets (crAPI, Juice Shop),
so the evaluation compares like-for-like.

## Why Nuclei

Nuclei represents the class of tool PentraAI is positioned against: a generic,
template-driven scanner that checks for known CVEs, misconfigurations, exposed
panels, and default credentials. It does **not** reason about business logic or
perform multi-step authenticated attacks (JWT forgery, cross-account object
access, SSRF payload chaining) the way PentraAI does — which is exactly the
comparison worth documenting.

---

## 1. Install Nuclei

You already have Docker Desktop running (for crAPI/Juice Shop), so Docker is the
fastest path — no Go toolchain needed.

```bash
docker pull projectdiscovery/nuclei:latest
```

Verify it works:
```bash
docker run --rm projectdiscovery/nuclei:latest -version
```

**Alternative (native binary, no Docker):** download the Windows zip from
https://github.com/projectdiscovery/nuclei/releases (latest release, asset named
`nuclei_<version>_windows_amd64.zip`), extract `nuclei.exe` somewhere on your
PATH, then run `nuclei -version` to confirm.

The first real scan auto-downloads the official templates repo (~a few thousand
YAML templates) into `~/.config/nuclei` (or `~/nuclei-templates`); this happens
once and is reused on every later run.

---

## 2. Run Nuclei against both targets

Because crAPI and Juice Shop are local Docker containers, use
`--network host` (Linux) — on Windows/Mac Docker Desktop, `localhost` from
inside the Nuclei container needs `host.docker.internal` instead of
`localhost`. The commands below use that form; adjust if you run the native
binary (then just use `localhost` directly).

We scan with a broad but non-destructive tag set: known CVEs, exposed panels,
misconfigurations, default logins, and generic vulnerability templates. We
explicitly exclude `dos`/`fuzz`/`intrusive` tags since these targets are shared
lab environments, not throwaway infrastructure.

```bash
mkdir -p results

# Juice Shop
docker run --rm -v "$(pwd)/results:/results" projectdiscovery/nuclei:latest \
  -u http://host.docker.internal:3001 \
  -tags cve,exposure,misconfig,default-login,tech,vuln \
  -exclude-tags dos,fuzz,intrusive \
  -je /results/juiceshop_nuclei.json \
  -severity info,low,medium,high,critical

# crAPI
docker run --rm -v "$(pwd)/results:/results" projectdiscovery/nuclei:latest \
  -u http://host.docker.internal:8888 \
  -tags cve,exposure,misconfig,default-login,tech,vuln \
  -exclude-tags dos,fuzz,intrusive \
  -je /results/crapi_nuclei.json \
  -severity info,low,medium,high,critical
```

**If using the native `nuclei.exe` instead of Docker**, just replace
`host.docker.internal` with `localhost` and drop the `docker run ...` wrapper:
```bash
nuclei -u http://localhost:3001 -tags cve,exposure,misconfig,default-login,tech,vuln ^
  -exclude-tags dos,fuzz,intrusive -je results\juiceshop_nuclei.json
```

Each scan typically takes a few minutes depending on template count and target
responsiveness. `-je` (json-export) writes a clean JSON array to the given file
— that's what the comparison script below reads.

---

## 3. Run the comparison

```bash
python compare_nuclei.py
```

This reads `results/{target}_nuclei.json` for both targets, reads your existing
PentraAI `results/{target}_findings.csv` (from the main benchmark — same folder
structure), and writes `results/nuclei_comparison.md`: a side-by-side table of
what each tool found, categorized by whether it falls inside PentraAI's five
target vulnerability classes (idor/BOLA, broken auth, ssrf, bfla, race) or
outside them (generic CVEs, exposed panels, misconfig, tech fingerprinting).

---

## 4. What to expect (and why)

Nuclei and PentraAI are not trying to catch the same bugs, which is the point of
running both:

- **Nuclei is expected to find:** exposed `/metrics` or `/actuator` endpoints,
  outdated library fingerprints, default credentials, missing security headers,
  known CVE signatures if the underlying framework/library version matches a
  template. These require no authentication and no multi-step logic.
- **Nuclei is expected to miss:** the crAPI/Juice Shop vulnerabilities in this
  benchmark almost entirely, because none of them are template-matchable —
  BOLA, JWT forgery, and SSRF-via-business-logic all require issuing two
  authenticated user sessions and comparing cross-account responses, which is
  outside what a signature/template scanner does.
- **PentraAI is expected to miss:** anything Nuclei's templates catch that
  isn't an authorization/auth/SSRF logic flaw — e.g. an outdated dependency with
  a known CVE — because PentraAI does not do CVE/version fingerprinting at all.

The conclusion this evaluation is built to support (fill in with your actual
numbers after running): **the two tools are complementary rather than
competing** — Nuclei covers infrastructure/dependency hygiene at high speed with
zero configuration, while PentraAI covers authenticated business-logic and
access-control flaws that require reasoning about application semantics, which
template-based scanning cannot express.