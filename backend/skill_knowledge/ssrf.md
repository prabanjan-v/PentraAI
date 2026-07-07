# SSRF — Server-Side Request Forgery (Detection Knowledge)

CWE: CWE-918 | OWASP: A10:2025 — Server-Side Request Forgery
Severity: High by default; Critical when it reaches cloud metadata or internal admin services.

## What it is
The server can be induced to make an HTTP(S) request to a destination the attacker
controls or should not be able to reach. Impact: read internal-only services, reach the
cloud metadata endpoint to steal IAM credentials, port-scan the internal network, or pivot
to other internal APIs. The defining property is that the REQUEST ORIGINATES FROM THE
SERVER, not the attacker's client.

## Where it lives (recon signals)
Any feature where the server fetches a URL you influence:
- Parameters named: url, uri, link, src, dest, redirect, next, target, host, domain,
  feed, rss, callback, webhook, api, endpoint, proxy, fetch, image/img/image_url, avatar,
  document, import, preview, render, download.
- Features: webhook configuration, "import from URL", URL preview/unfurl, PDF/screenshot
  generators, image-fetch-by-URL, link validators, and integrations.
- crAPI specific: `POST /workshop/api/merchant/contact_mechanic` with a `mechanic_api`
  field that the server fetches server-side.

## High-value payloads
- AWS metadata:   http://169.254.169.254/latest/meta-data/  (and /latest/api/token for IMDSv2)
- AWS IAM creds:  http://169.254.169.254/latest/meta-data/iam/security-credentials/
- GCP metadata:   http://metadata.google.internal/computeMetadata/v1/   (needs header Metadata-Flavor: Google)
- Alibaba:        http://100.100.100.200/latest/meta-data/
- Internal:       http://127.0.0.1:<port>/ , http://localhost/ , internal service hostnames
- Bypass tricks:  decimal/hex IP (http://2130706433/), [::], 0.0.0.0, DNS rebinding,
  http://127.0.0.1.nip.io, adding @ (http://expected@169.254.169.254), URL-encoding.

## How to CONFIRM (low false-positive)
An input is SSRF only if the SERVER actually makes the request. Evidence:
1. Leaked content: the response contains internal/metadata content that only a server-side
   fetch could retrieve (e.g. metadata keys like `ami-id`, `instance-id`, `iam`,
   `computeMetadata`, or an internal service's response body).
2. Server-side fetch behaviour: connection errors about the injected host that only occur
   when the server dials it — "connection refused", "could not resolve host",
   "connection timed out", "no route to host". A closed internal port returning "connection
   refused" while an external host returns content is strong differential proof.
3. Out-of-band: the server calls a unique attacker-controlled URL (needs an OOB collaborator).

Do NOT flag: client-side validation messages, reflected input echoed without a fetch, or an
app that simply rejects the URL. Reflection alone is not SSRF.

## Remediation (for the report)
Enforce an allowlist of permitted hosts/schemes; block RFC1918, loopback, link-local
(169.254.0.0/16), and metadata IPs; resolve the hostname and re-validate the resolved IP
(defeat DNS rebinding); disable unused URL schemes (file://, gopher://, dict://); require
IMDSv2; and never send raw fetched responses back to the client.