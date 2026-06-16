"""
recon.py — Phase 1: Enhanced Reconnaissance
Works on ANY target — bug bounty, Juice Shop, DVWA, real apps.

5 discovery techniques run in parallel:
  1. Common path probing        — fast sweep of known API paths
  2. Wayback Machine lookup     — archive.org reveals old/hidden endpoints
  3. Wordlist fuzzing           — 200+ common API paths tried automatically
  4. Subdomain enumeration      — finds api.target.com, staging.target.com etc.
  5. Deep JS analysis           — reads bundled JS to find hidden API calls
  + HTML parsing (links, forms, hidden fields)
  + robots.txt and sitemap.xml
  + JavaScript inline API extraction
"""

import re
import asyncio
import httpx
import socket
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from config import settings


# ── Built-in wordlist (no external file needed) ───────────────────
# 200+ common API paths used across frameworks
FUZZ_PATHS = [
    # Authentication
    "/api/auth/login", "/api/auth/register", "/api/auth/logout",
    "/api/auth/refresh", "/api/auth/token", "/api/auth/me",
    "/api/auth/password/reset", "/api/auth/verify",
    "/login", "/logout", "/register", "/signup", "/signin",
    # Users
    "/api/users", "/api/users/me", "/api/users/profile",
    "/api/users/1", "/api/users/2", "/api/users/3",
    "/api/user", "/api/user/me", "/api/user/profile",
    "/api/v1/users", "/api/v2/users", "/api/v1/user",
    "/api/v1/users/me", "/api/v2/users/me",
    "/rest/user/whoami", "/rest/user/data-export",
    # Admin
    "/api/admin", "/api/admin/users", "/api/admin/dashboard",
    "/api/admin/settings", "/api/admin/logs",
    "/api/v1/admin", "/api/v2/admin",
    "/admin", "/administration", "/manage", "/manager",
    # Common data endpoints
    "/api/orders", "/api/orders/1", "/api/orders/2",
    "/api/products", "/api/products/1",
    "/api/payments", "/api/transactions", "/api/invoices",
    "/api/messages", "/api/notifications", "/api/comments",
    "/api/posts", "/api/articles", "/api/blogs",
    "/api/accounts", "/api/wallet", "/api/cart", "/api/basket",
    "/api/checkout", "/api/subscriptions", "/api/reports",
    "/api/customers", "/api/vendors", "/api/partners",
    "/api/items", "/api/catalog", "/api/inventory",
    "/api/search", "/api/export", "/api/import",
    "/api/permissions", "/api/roles", "/api/groups",
    "/api/webhooks", "/api/integrations", "/api/analytics",
    # Files
    "/api/upload", "/api/files", "/api/documents",
    "/api/images", "/api/attachments", "/api/media",
    # Config / status
    "/api/config", "/api/settings", "/api/status",
    "/api/health", "/health", "/status", "/ping",
    "/api/version", "/api/info", "/api/metrics",
    # GraphQL
    "/graphql", "/api/graphql", "/query", "/api/query",
    # API versioning
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/api/v1/auth/login", "/api/v2/auth/login",
    "/api/v1/auth/register",
    # API documentation
    "/swagger.json", "/swagger-ui.html", "/swagger",
    "/openapi.json", "/v3/api-docs", "/api-docs",
    "/docs", "/redoc", "/api/docs",
    # Sensitive files (often accidentally exposed)
    "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/config.json", "/config.yml",
    "/package.json", "/composer.json",
    "/backup.sql", "/dump.sql",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    # Juice Shop specific
    "/api/Users", "/api/Users/1", "/api/Users/2",
    "/api/Complaints", "/api/Complaints/1",
    "/api/Challenges", "/api/BasketItems",
    "/rest/basket/1", "/rest/basket/2",
    "/rest/products/search", "/rest/user/login",
    # DVWA specific
    "/dvwa", "/vulnerabilities", "/dvwa/login.php",
    # WordPress (very common)
    "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
    "/wp-admin", "/wp-login.php",
    # Laravel / PHP
    "/api/sanctum/csrf-cookie",
    # Django
    "/api-auth/login/",
    # Spring Boot
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings",
]

# Common subdomains to enumerate
COMMON_SUBDOMAINS = [
    "api", "api2", "api-v2", "staging", "stage",
    "dev", "development", "test", "testing", "qa",
    "beta", "alpha", "sandbox", "demo", "uat",
    "admin", "dashboard", "portal", "app", "apps",
    "mobile", "m", "internal", "intranet",
    "auth", "login", "accounts", "account", "sso",
    "backend", "server", "services", "microservice",
    "old", "legacy", "v1", "v2", "v3",
    "secure", "ssl", "mail", "smtp",
    "cdn", "static", "assets",
]


# ── Main entry point ──────────────────────────────────────────────

async def run_recon(target_url: str) -> dict:
    """
    Enhanced reconnaissance — runs all 5 techniques in parallel.
    Works on any target, not just known test apps.

    Args:
        target_url: Full URL of the target (e.g. "http://localhost:3001")

    Returns:
        Structured dict with all discovered endpoints, patterns, forms etc.
    """
    target_url = target_url.rstrip("/")
    parsed     = urlparse(target_url)
    domain     = parsed.netloc
    scheme     = parsed.scheme

    results = {
        "target_url":      target_url,
        "domain":          domain,
        "alive_endpoints": [],
        "tech_stack":      {},
        "id_patterns":     [],
        "forms":           [],
        "api_spec_found":  False,
        "robots_paths":    [],
        "all_links":       [],
        "subdomains":      [],
        "wayback_urls":    [],
        "js_endpoints":    [],
        "sources":         {},  # Which technique found what
    }

    async with httpx.AsyncClient(
        timeout=settings.request_timeout,
        follow_redirects=True,
        verify=False,
    ) as client:

        # ── Run all techniques concurrently ───────────────────────
        print("RECON: Starting all discovery techniques in parallel...")

        tasks = [
            _technique_1_probe(client, target_url),
            _technique_2_wayback(client, domain),
            _technique_3_fuzz(client, target_url),
            _technique_4_subdomains(domain, scheme),
            _technique_5_js(client, target_url),
            _parse_html(client, target_url),
            _read_robots(client, target_url),
            _read_sitemap(client, target_url),
            _fingerprint(client, target_url),
            _find_api_spec(client, target_url),
        ]

        (
            probe_results,
            wayback_results,
            fuzz_results,
            subdomain_results,
            js_results,
            html_results,
            robots_results,
            sitemap_results,
            tech_stack,
            api_spec,
        ) = await asyncio.gather(*tasks, return_exceptions=True)

        # ── Merge all results ─────────────────────────────────────

        def _safe(r, default):
            return r if not isinstance(r, Exception) else default

        probe_results     = _safe(probe_results,    [])
        wayback_results   = _safe(wayback_results,  [])
        fuzz_results      = _safe(fuzz_results,     [])
        subdomain_results = _safe(subdomain_results,[])
        js_results        = _safe(js_results,       [])
        html_results      = _safe(html_results,     {})
        robots_results    = _safe(robots_results,   [])
        sitemap_results   = _safe(sitemap_results,  [])
        tech_stack        = _safe(tech_stack,       {})
        api_spec          = _safe(api_spec,         {})

        # Log what each technique found
        print(f"RECON: Probe found {len(probe_results)} endpoints")
        print(f"RECON: Wayback Machine found {len(wayback_results)} historical URLs")
        print(f"RECON: Wordlist fuzzing found {len(fuzz_results)} endpoints")
        print(f"RECON: Subdomains found {len(subdomain_results)}")
        print(f"RECON: JS analysis found {len(js_results)} API calls")

        # Combine all endpoints into one deduplicated list
        all_endpoints = list(set(
            probe_results +
            fuzz_results +
            html_results.get("links", []) +
            sitemap_results
        ))

        results["alive_endpoints"] = all_endpoints[:settings.max_endpoints]
        results["tech_stack"]      = tech_stack
        results["forms"]           = html_results.get("forms", [])
        results["all_links"]       = html_results.get("links", [])
        results["robots_paths"]    = robots_paths = robots_results
        results["wayback_urls"]    = wayback_results[:50]
        results["js_endpoints"]    = js_results
        results["subdomains"]      = subdomain_results
        results["api_spec_found"]  = api_spec.get("found", False)
        results["sources"] = {
            "probe":    len(probe_results),
            "wayback":  len(wayback_results),
            "fuzz":     len(fuzz_results),
            "subdomains": len(subdomain_results),
            "js":       len(js_results),
        }

        # Build ID patterns from ALL discovered URLs
        all_urls = list(set(
            all_endpoints +
            wayback_results +
            js_results +
            [target_url + p for p in robots_results]
        ))
        results["id_patterns"] = _find_id_patterns(all_urls)

    total = len(results["alive_endpoints"])
    patterns = len(results["id_patterns"])
    subs = len(results["subdomains"])
    print(f"RECON: Complete — {total} endpoints, {patterns} ID patterns, {subs} subdomains")

    return results


# ── Technique 1: Common path probing ─────────────────────────────

async def _technique_1_probe(
    client: httpx.AsyncClient,
    base_url: str,
) -> list[str]:
    """
    Quickly probe a list of known-common paths.
    Runs all requests concurrently for speed.
    """
    PROBE_PATHS = [
        "/", "/api", "/api/v1", "/api/v2", "/api/v3",
        "/graphql", "/swagger.json", "/openapi.json",
        "/api-docs", "/v3/api-docs", "/docs",
        "/robots.txt", "/sitemap.xml", "/.env",
        "/admin", "/api/users", "/api/orders",
        "/api/products", "/health", "/status",
        "/api/Users", "/api/Users/1",       # Juice Shop
        "/rest/user/whoami",                 # Juice Shop
        "/actuator/health",                  # Spring Boot
        "/dvwa",                             # DVWA
    ]

    alive = []

    async def probe(path):
        try:
            r = await client.get(base_url + path, timeout=5)
            if r.status_code not in [404, 400]:
                alive.append(base_url + path)
        except Exception:
            pass

    await asyncio.gather(*[probe(p) for p in PROBE_PATHS])
    return alive


# ── Technique 2: Wayback Machine ─────────────────────────────────

async def _technique_2_wayback(
    client: httpx.AsyncClient,
    domain: str,
) -> list[str]:
    """
    Query archive.org CDX API for all historical URLs of this domain.
    These often include old/deprecated API endpoints still active.

    API docs: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
    """
    try:
        # Filter to likely API endpoints, limit to 300 results
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*"
            f"&output=json"
            f"&fl=original"
            f"&collapse=urlkey"
            f"&limit=300"
            f"&filter=statuscode:200"
        )

        r = await client.get(url, timeout=15)
        if r.status_code != 200:
            return []

        raw = r.json()
        if not raw or len(raw) < 2:
            return []

        # First row is headers, rest are data rows
        urls = [row[0] for row in raw[1:] if row]

        # Filter to likely API/interesting endpoints
        interesting = []
        for u in urls:
            if any(word in u for word in [
                "/api/", "/rest/", "/v1/", "/v2/", "/v3/",
                "/admin", "/user", "/order", "/payment",
                ".json", ".xml", "token", "auth",
            ]):
                interesting.append(u)

        return list(set(interesting))[:100]

    except Exception as e:
        print(f"RECON: Wayback Machine unavailable: {e}")
        return []


# ── Technique 3: Wordlist fuzzing ─────────────────────────────────

async def _technique_3_fuzz(
    client: httpx.AsyncClient,
    base_url: str,
) -> list[str]:
    """
    Try all 200+ paths in FUZZ_PATHS concurrently.
    Returns only the ones that respond with non-404 status.
    More thorough than basic probing.
    """
    alive = []

    async def fuzz(path):
        try:
            r = await client.get(base_url + path, timeout=5)
            if r.status_code not in [404, 400, 410]:
                # Filter out redirects to login pages
                if r.status_code in [200, 201, 403, 401, 422, 500]:
                    alive.append(base_url + path)
        except Exception:
            pass

    # Run in batches of 20 to avoid overwhelming the server
    batch_size = 20
    for i in range(0, len(FUZZ_PATHS), batch_size):
        batch = FUZZ_PATHS[i:i + batch_size]
        await asyncio.gather(*[fuzz(p) for p in batch])

    return alive


# ── Technique 4: Subdomain enumeration ───────────────────────────

async def _technique_4_subdomains(
    domain: str,
    scheme: str,
) -> list[str]:
    """
    Try common subdomain names via DNS resolution.
    Returns subdomains that actually resolve to an IP.

    Why this matters: api.target.com is often less protected
    than www.target.com — different security controls, older code.
    """
    # Skip for localhost — no subdomains to enumerate
    if "localhost" in domain or domain.replace(".", "").isdigit():
        return []

    # Strip port from domain if present
    base_domain = domain.split(":")[0]

    # Remove www. prefix to get root domain
    if base_domain.startswith("www."):
        base_domain = base_domain[4:]

    found = []

    async def check_subdomain(sub):
        full_domain = f"{sub}.{base_domain}"
        try:
            # DNS lookup — if it resolves, the subdomain exists
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(full_domain, 80, socket.AF_INET)
            )
            found.append(f"{scheme}://{full_domain}")
            print(f"RECON: Subdomain found → {full_domain}")
        except socket.gaierror:
            pass  # Does not resolve — does not exist
        except Exception:
            pass

    # Run subdomain checks concurrently in batches
    batch_size = 15
    for i in range(0, len(COMMON_SUBDOMAINS), batch_size):
        batch = COMMON_SUBDOMAINS[i:i + batch_size]
        await asyncio.gather(*[check_subdomain(s) for s in batch])

    return found


# ── Technique 5: Deep JS analysis ────────────────────────────────

async def _technique_5_js(
    client: httpx.AsyncClient,
    target_url: str,
) -> list[str]:
    """
    Download and parse JavaScript files to find API endpoints.

    Modern apps bundle all their code into JS files.
    These bundles contain every API call the frontend makes —
    including ones not visible in the HTML or network traffic.

    Finds patterns like:
      fetch("/api/users/me")
      axios.get(`/api/orders/${id}`)
      this.http.get('/api/admin/settings')
    """
    discovered = []

    try:
        # Get the homepage HTML first
        r = await client.get(target_url, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")

        # Find all external JS file URLs
        js_urls = []
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src:
                if src.startswith("http"):
                    js_urls.append(src)
                elif src.startswith("/"):
                    js_urls.append(target_url + src)
                elif src.startswith("./") or src.startswith("../"):
                    js_urls.append(urljoin(target_url + "/", src))

            # Also check inline script content
            if script.string:
                discovered.extend(_extract_api_from_js(script.string, target_url))

        # Download and parse each JS file (limit to 8)
        print(f"RECON: JS analysis — found {len(js_urls)} JS files to parse")

        async def analyse_js(js_url):
            try:
                r = await client.get(js_url, timeout=8)
                if r.status_code == 200:
                    endpoints = _extract_api_from_js(r.text, target_url)
                    discovered.extend(endpoints)
            except Exception:
                pass

        await asyncio.gather(*[analyse_js(u) for u in js_urls[:8]])

    except Exception as e:
        print(f"RECON: JS analysis error: {e}")

    # Deduplicate and filter to real API paths
    unique = list(set(discovered))
    api_paths = [
        u for u in unique
        if any(word in u for word in ["/api/", "/rest/", "/v1/", "/v2/", "/graphql"])
    ]

    return api_paths[:50]


def _extract_api_from_js(js_text: str, base_url: str) -> list[str]:
    """
    Extract API endpoint paths from JavaScript source code.
    Uses regex to find common patterns.
    """
    endpoints = []

    # Patterns to search for in JS
    patterns = [
        # fetch("/api/users")
        r'fetch\(["\`]([/][^"\`\s,)]+)["\`]',
        # axios.get("/api/users")
        r'axios\.\w+\(["\`]([/][^"\`\s,)]+)["\`]',
        # this.http.get("/api/users")
        r'\.(?:get|post|put|delete|patch)\(["\`]([/][^"\`\s,)]+)["\`]',
        # "/api/users" standalone strings
        r'["\`](\/api\/[\w\/\-\.]+)["\`]',
        r'["\`](\/rest\/[\w\/\-\.]+)["\`]',
        r'["\`](\/v\d\/[\w\/\-\.]+)["\`]',
        # url: "/api/users"
        r'url:\s*["\`]([/][^"\`\s,}]+)["\`]',
        # baseURL + "/users"
        r'["\`](\/[\w\/\-\{\}]+\/[\w\-]+)["\`]',
    ]

    for pattern in patterns:
        found = re.findall(pattern, js_text)
        for path in found:
            # Filter out obvious non-API paths
            if not any(ext in path for ext in [
                ".js", ".css", ".png", ".jpg", ".svg",
                ".ico", ".woff", ".ttf", ".map",
            ]):
                if len(path) > 3 and len(path) < 100:
                    endpoints.append(base_url + path)

    return endpoints


# ── HTML parsing ──────────────────────────────────────────────────

async def _parse_html(
    client: httpx.AsyncClient,
    target_url: str,
) -> dict:
    """Extract links and forms from the HTML page."""
    try:
        r = await client.get(target_url, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        base_domain = urlparse(target_url).netloc

        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full = urljoin(target_url, href)
            if urlparse(full).netloc == base_domain:
                links.append(full)

        forms = []
        for form in soup.find_all("form"):
            fields = {}
            for inp in form.find_all(["input", "select", "textarea"]):
                name  = inp.get("name") or inp.get("id", "")
                value = inp.get("value", "")
                ftype = inp.get("type", "text")
                if name:
                    fields[name] = {
                        "value": value, "type": ftype,
                        "hidden": ftype == "hidden",
                    }
            action = urljoin(target_url, form.get("action", ""))
            method = form.get("method", "GET").upper()
            if fields:
                forms.append({
                    "action": action, "method": method,
                    "fields": fields,
                    "has_hidden": any(f["hidden"] for f in fields.values()),
                })

        return {"links": list(set(links))[:50], "forms": forms}

    except Exception:
        return {"links": [], "forms": []}


# ── Robots.txt ────────────────────────────────────────────────────

async def _read_robots(client: httpx.AsyncClient, base_url: str) -> list[str]:
    """Parse robots.txt for disallowed paths."""
    try:
        r = await client.get(base_url + "/robots.txt", timeout=5)
        if r.status_code == 200:
            paths = []
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        paths.append(path)
            return paths
    except Exception:
        pass
    return []


# ── Sitemap.xml ───────────────────────────────────────────────────

async def _read_sitemap(client: httpx.AsyncClient, base_url: str) -> list[str]:
    """Parse sitemap.xml for all URLs."""
    urls = []
    try:
        r = await client.get(base_url + "/sitemap.xml", timeout=5)
        if r.status_code == 200:
            found = re.findall(r"<loc>(.*?)</loc>", r.text)
            urls.extend(found[:50])
    except Exception:
        pass
    return urls


# ── Tech fingerprint ──────────────────────────────────────────────

async def _fingerprint(client: httpx.AsyncClient, base_url: str) -> dict:
    """Detect tech stack from response headers."""
    tech = {}
    try:
        r = await client.get(base_url, timeout=5)
        headers = r.headers
        body    = r.text.lower()

        powered = headers.get("x-powered-by", "").lower()
        server  = headers.get("server", "").lower()
        cookie  = str(headers.get("set-cookie", "")).lower()

        if "express"    in powered: tech["framework"] = "Node.js / Express"
        elif "php"      in powered: tech["framework"] = "PHP"
        elif "asp.net"  in powered: tech["framework"] = "ASP.NET"
        elif "next.js"  in powered: tech["framework"] = "Next.js"

        if "nginx"      in server:  tech["server"] = "nginx"
        elif "apache"   in server:  tech["server"] = "Apache"
        elif "gunicorn" in server:  tech["server"] = "Python / Gunicorn"
        elif "iis"      in server:  tech["server"] = "IIS"

        if "jsessionid" in cookie:  tech["language"] = "Java"
        elif "phpsessid" in cookie: tech["language"] = "PHP"
        elif "connect.sid" in cookie: tech["language"] = "Node.js"
        elif "csrftoken" in cookie: tech["language"] = "Python / Django"

        if "graphql"    in body:    tech["graphql"] = True
        if "swagger"    in body:    tech["swagger"] = True
        if "juice shop" in body:    tech["app"] = "OWASP Juice Shop"
        if "dvwa"       in body:    tech["app"] = "DVWA"

        # Detect auth type
        if "bearer" in str(r.headers).lower() or "jwt" in body:
            tech["auth"] = "JWT / Bearer"
        elif "oauth" in body:
            tech["auth"] = "OAuth 2.0"

    except Exception:
        pass
    return tech


# ── API spec ──────────────────────────────────────────────────────

async def _find_api_spec(client: httpx.AsyncClient, base_url: str) -> dict:
    """Check for Swagger/OpenAPI spec — gives us the full API map."""
    paths = [
        "/swagger.json", "/openapi.json",
        "/api-docs", "/v3/api-docs",
        "/docs/swagger.json",
    ]
    for path in paths:
        try:
            r = await client.get(base_url + path, timeout=5)
            if r.status_code == 200 and "paths" in r.text:
                print(f"RECON: API spec found at {path} — full endpoint map available")
                return {"found": True, "url": base_url + path}
        except Exception:
            pass
    return {"found": False}


# ── ID pattern detection ──────────────────────────────────────────

def _find_id_patterns(urls: list[str]) -> list[dict]:
    """
    Detect endpoints that contain ID patterns.
    These are the primary IDOR test targets.
    Handles: numeric IDs, UUIDs, base64-encoded IDs.
    """
    patterns = []
    seen = set()

    for url in urls:
        # Numeric ID: /api/orders/101
        match = re.search(r"(/[a-zA-Z\-_]+)/(\d+)(?:/|$|\?)", url)
        if match:
            template = re.sub(r"/\d+", "/{id}", url)
            if template not in seen:
                seen.add(template)
                patterns.append({
                    "type":     "numeric",
                    "template": template,
                    "example":  url,
                    "id_value": match.group(2),
                    "endpoint": match.group(1),
                })

        # UUID: /api/users/550e8400-e29b-41d4-a716-446655440000
        elif re.search(
            r"/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            url, re.I
        ):
            template = re.sub(
                r"/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                "/{uuid}", url, flags=re.I
            )
            if template not in seen:
                seen.add(template)
                patterns.append({
                    "type":     "uuid",
                    "template": template,
                    "example":  url,
                })

        # Base64-like encoded ID
        elif re.search(r"/([A-Za-z0-9+/]{12,}={0,2})$", url):
            if url not in seen:
                seen.add(url)
                patterns.append({
                    "type":    "encoded",
                    "template": url,
                    "example":  url,
                    "note":    "Possible base64-encoded ID",
                })

    return patterns
