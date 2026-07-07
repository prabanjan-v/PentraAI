## Benchmark scores — OWASP Juice Shop

_Scored 2026-07-07 from `juiceshop_findings.csv`._

| Metric | Value |
|---|---|
| In-scope known vulns | 6 |
| Detected (unique) | 2 |
| True positives (findings) | 3 |
| False positives (findings) | 0 |
| **Detection rate** (detected / in-scope) | **33%** |
| **Precision** (TP / (TP+FP)) | **100%** |
| **False-positive rate** (FP / all findings) | **0%** |

### Per-module breakdown

| Module | In-scope | Detected | TP | FP | Missed (FN) |
|---|---|---|---|---|---|
| bfla | 0 | 0 | 1 | 0 | — |
| broken_auth | 2 | 1 | 1 | 0 | js-auth-2 |
| idor | 3 | 1 | 1 | 0 | js-idor-2, js-idor-3 |
| ssrf | 1 | 0 | 0 | 0 | js-ssrf-1 |
