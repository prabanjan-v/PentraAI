# BFLA — Broken Function-Level Authorization  (Detection Knowledge)

CWE: CWE-285 / CWE-863 | OWASP API5:2023 Broken Function Level Authorization / A01:2025 Broken Access Control
Severity: High by default; Critical when the exposed function is administrative (delete users,
read all records, change roles).

## What it is
The application enforces authentication but not *function-level* authorization: a lower-privilege
user (or an unauthenticated client) can invoke a function meant only for admins/staff/another
role. Distinct from BOLA/IDOR (which is object-level — accessing another user's *object*); BFLA
is about invoking a privileged *operation/endpoint* you should not be allowed to call at all.

## Where it lives (recon signals)
- Endpoints in a privileged namespace: /admin, /administrator, /manage, /management, /internal,
  /moderator, /staff, /dashboard, /actuator, /console, and role-specific services (e.g. a
  "mechanic" or "merchant" service a normal user should not reach).
- Privileged actions by name: users/all, orders/all, export, backup, approve, ban, suspend,
  promote, grant, role, permission, config, audit, delete.
- HTTP-method escalation: a normal user allowed to GET a resource but also able to PUT/DELETE it,
  or to POST to an admin action.

## How to test
1. Establish a LOW-privilege session (an ordinary user token) and also try UNAUTHENTICATED.
2. Call each privileged-looking endpoint with (a) the low-priv token and (b) no token.
3. A correctly-secured privileged function returns 401 or 403 to both.
4. If it returns 200/201 with privileged data or performs the privileged action, that is BFLA.

## How to CONFIRM (low false-positive)
Flag ONLY when BOTH are true:
 - the endpoint is genuinely privileged (admin namespace or a privileged action — not a public
   listing like /products or /health), AND
 - a user who should be denied receives a success (200/201) with privileged content or a
   completed privileged action.
Do NOT flag: public endpoints, endpoints that correctly return 401/403, login/register/health,
or generic content that any user is meant to see. A 200 on a public route is not BFLA.

## Severity guide
- Read of all users / all orders / other roles' data  → High.
- Admin actions (delete/ban/promote/role change, config) reachable by a normal user → Critical.
- Method escalation on own-tier resources → High/Medium depending on impact.

## Remediation (for the report)
Enforce authorization on every function server-side, denying by default. Check the caller's role
for each privileged operation (not just that they are logged in). Do not rely on the UI hiding
admin actions. Apply the same checks to every HTTP method. Centralise access control so new
endpoints inherit deny-by-default.