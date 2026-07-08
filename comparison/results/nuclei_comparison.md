# PentraAI vs Nuclei — Comparison Results

## Summary

| Target | Nuclei findings | Nuclei in PentraAI's scope | PentraAI TPs |
|---|---|---|---|
| juiceshop | 16 | 0 | 3 |
| crapi | 15 | 0 | 6 |

## juiceshop

### Nuclei findings by severity
| Severity | Count |
|---|---|
| info | 15 |
| medium | 1 |

### Nuclei findings that overlap PentraAI's target classes (IDOR/auth/SSRF/BFLA/race)
_None — no Nuclei finding matched PentraAI's authorization/auth/SSRF/BFLA/race classes._

### Nuclei findings outside PentraAI's scope (generic CVE/exposure/misconfig/tech)
| Template | Name | Severity |
|---|---|---|
| swagger-api | Public Swagger API - Detect | info |
| prometheus-metrics | Prometheus Metrics - Detect | medium |
| x-recruiting-header | X-Recruiting Header | info |
| addeventlistener-detect | Add DOM EventListener - Detection | info |
| owasp-juice-shop-detect | OWASP Juice Shop | info |
| security-txt | security.txt File | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| fingerprinthub-web-fingerprints | FingerprintHub Technology Fingerprint | info |
| robots-txt | robots.txt file | info |

### PentraAI true positives (from the main benchmark)
| Module | Vulnerability | gt_id |
|---|---|---|
| idor | IDOR / Broken Object Level Authorization (BOLA) — Basket Manipulation (HTTP Parameter Pollution) | js-idor-1 |
| bfla | Broken Function-Level Authorization (BFLA) | js-bfla-1 |
| broken_auth | Broken Auth — JWT Algorithm None Attack | js-auth-1 |

## crapi

### Nuclei findings by severity
| Severity | Count |
|---|---|
| high | 3 |
| info | 12 |

### Nuclei findings that overlap PentraAI's target classes (IDOR/auth/SSRF/BFLA/race)
_None — no Nuclei finding matched PentraAI's authorization/auth/SSRF/BFLA/race classes._

### Nuclei findings outside PentraAI's scope (generic CVE/exposure/misconfig/tech)
| Template | Name | Severity |
|---|---|---|
| codeigniter-env | Codeigniter - .env File Discovery | high |
| laravel-env | Laravel - Sensitive Information Disclosure | high |
| generic-env | Generic Env File Disclosure | high |
| robots-txt | robots.txt file | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| http-missing-security-headers | HTTP Missing Security Headers | info |
| openresty-detect | OpenResty detection | info |

### PentraAI true positives (from the main benchmark)
| Module | Vulnerability | gt_id |
|---|---|---|
| idor | IDOR / Broken Object Level Authorization (BOLA) — Vehicle Location | crapi-idor-1 |
| idor | IDOR / Broken Object Level Authorization (BOLA) — Mechanic Report | crapi-idor-2 |
| broken_auth | Broken Auth — JWT Algorithm None Attack | crapi-auth-1 |
| broken_auth | Broken Auth — JWT Algorithm Confusion (RS256→HS256) | crapi-auth-1 |
| bfla | Broken Function-Level Authorization (BFLA) | crapi-ssrf-1 |
| ssrf | Server-Side Request Forgery (SSRF) | crapi-bfla-1 |

## Interpretation

Nuclei's findings (if any landed in PentraAI's scope column above) are almost always coincidental — e.g. a default-login template matching an exposed panel — rather than the authenticated, multi-step logic PentraAI performs (harvesting a victim's object id, forging a JWT, comparing two authenticated sessions' responses). Conversely, PentraAI does not fingerprint CVEs or check for outdated dependencies, which is Nuclei's core strength. The two tools cover different, complementary parts of a real assessment's scope.