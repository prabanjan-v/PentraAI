## Benchmark scores — OWASP crAPI

_Scored 2026-07-07 from `crapi_findings.csv`._

| Metric | Value |
|---|---|
| In-scope known vulns | 6 |
| Detected (unique) | 5 |
| True positives (findings) | 6 |
| False positives (findings) | 0 |
| **Detection rate** (detected / in-scope) | **83%** |
| **Precision** (TP / (TP+FP)) | **100%** |
| **False-positive rate** (FP / all findings) | **0%** |

### Per-module breakdown

| Module | In-scope | Detected | TP | FP | Missed (FN) |
|---|---|---|---|---|---|
| bfla | 1 | 1 | 1 | 0 | — |
| broken_auth | 1 | 1 | 2 | 0 | — |
| idor | 2 | 2 | 2 | 0 | — |
| race_condition | 1 | 0 | 0 | 0 | crapi-race-1 |
| ssrf | 1 | 1 | 1 | 0 | — |
