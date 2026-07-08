"""
html_report.py — Generate a clean, readable HTML report from scan findings.

The report is designed for BOTH audiences:
  - Non-technical readers: plain-English "What this means" + "Why it matters"
  - Technical readers: exact payloads, requests, responses, remediation code

Each finding shows:
  1. Plain-English explanation
  2. Severity and impact
  3. The exact payload/technique used
  4. The request sent and response received
  5. How to fix it

Output: a standalone HTML file with embedded CSS (no external dependencies).
"""

import json
import html
from datetime import datetime


# Plain-English descriptions for each vulnerability type
VULN_EXPLANATIONS = {
    "idor": {
        "simple": "One user can see or change another user's private data just by changing a number or ID in the request. Imagine being able to read someone else's bank statement by changing the account number in the web address.",
        "impact": "Attackers can steal personal data, view other customers' orders, or modify accounts that do not belong to them.",
    },
    "broken_auth": {
        "simple": "The login system can be tricked into accepting fake credentials. It is like a security guard who accepts an obviously forged ID card without checking it properly.",
        "impact": "Attackers can log in as any user — including administrators — without knowing their password, gaining full control of accounts.",
    },
    "race_condition": {
        "simple": "When many requests are sent at the exact same moment, the system processes all of them before it can update its records. It is like withdrawing money from 30 ATMs simultaneously before any of them notice the balance dropped.",
        "impact": "Attackers can use a discount coupon many times, place more orders than their balance allows, or bypass limits that should apply only once.",
    },
    "missing_rate_limit": {
        "simple": "The system does not limit how many times an action can be performed in a short time. It is like a door that lets an unlimited crowd push through all at once.",
        "impact": "Attackers can spam the system, abuse forms, or overwhelm a service with automated requests.",
    },
}

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#ca8a04",
    "low":      "#16a34a",
    "info":     "#6b7280",
}


def generate_html_report(report: dict) -> str:
    """Build a complete standalone HTML report from the scan report dict."""

    target     = report.get("target", "Unknown target")
    findings   = report.get("findings", [])
    summary    = report.get("executive_summary", "")
    tech_stack = report.get("tech_stack", {})
    timestamp  = datetime.now().strftime("%d %B %Y, %H:%M")

    critical = report.get("critical", 0)
    high     = report.get("high", 0)
    medium   = report.get("medium", 0)
    low      = report.get("low", 0)
    total    = report.get("total_findings", 0)

    tech_str = ", ".join(f"{k}: {v}" for k, v in tech_stack.items()) or "Not identified"

    findings_html = ""
    for i, finding in enumerate(findings, 1):
        findings_html += _render_finding(i, finding)

    if not findings:
        findings_html = """
        <div class="no-findings">
            <h2>No vulnerabilities detected</h2>
            <p>This scan did not find any of the vulnerability classes it tests for.
            Note: this does not guarantee the application is fully secure —
            manual testing by a security professional is always recommended.</p>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PentraAI Security Report — {html.escape(target)}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        line-height: 1.6; color: #1f2937; background: #f3f4f6; padding: 0;
    }}
    .container {{ max-width: 900px; margin: 0 auto; padding: 0 20px 60px; }}

    /* Header */
    .header {{
        background: linear-gradient(135deg, #1e3a8a 0%, #3730a3 100%);
        color: white; padding: 40px 20px; text-align: center;
    }}
    .header h1 {{ font-size: 28px; margin-bottom: 8px; }}
    .header .subtitle {{ font-size: 15px; opacity: 0.85; }}
    .header .target {{
        font-size: 14px; margin-top: 16px; padding: 8px 16px;
        background: rgba(255,255,255,0.15); border-radius: 6px;
        display: inline-block; font-family: monospace;
    }}

    /* Summary cards */
    .summary-cards {{
        display: flex; gap: 12px; justify-content: center;
        margin: -30px auto 30px; flex-wrap: wrap; max-width: 900px;
        padding: 0 20px;
    }}
    .card {{
        background: white; border-radius: 10px; padding: 20px 28px;
        text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        min-width: 110px;
    }}
    .card .number {{ font-size: 32px; font-weight: 700; }}
    .card .label {{ font-size: 13px; color: #6b7280; margin-top: 4px;
        text-transform: uppercase; letter-spacing: 0.5px; }}
    .card.critical .number {{ color: #dc2626; }}
    .card.high .number {{ color: #ea580c; }}
    .card.medium .number {{ color: #ca8a04; }}
    .card.total .number {{ color: #1e3a8a; }}

    /* Executive summary */
    .exec-summary {{
        background: white; border-radius: 10px; padding: 28px;
        margin-bottom: 30px; box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    }}
    .exec-summary h2 {{
        font-size: 18px; margin-bottom: 12px; color: #1e3a8a;
        display: flex; align-items: center; gap: 8px;
    }}
    .exec-summary .meta {{
        font-size: 13px; color: #6b7280; margin-top: 16px;
        padding-top: 16px; border-top: 1px solid #e5e7eb;
    }}

    /* Findings */
    .finding {{
        background: white; border-radius: 10px; margin-bottom: 24px;
        overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.06);
        border-left: 5px solid #6b7280;
    }}
    .finding.critical {{ border-left-color: #dc2626; }}
    .finding.high {{ border-left-color: #ea580c; }}
    .finding.medium {{ border-left-color: #ca8a04; }}
    .finding.low {{ border-left-color: #16a34a; }}

    .finding-header {{ padding: 20px 24px; background: #fafafa;
        border-bottom: 1px solid #e5e7eb; }}
    .finding-header .title-row {{
        display: flex; justify-content: space-between;
        align-items: center; gap: 12px; flex-wrap: wrap;
    }}
    .finding-header h3 {{ font-size: 17px; color: #111827; }}
    .severity-badge {{
        padding: 4px 12px; border-radius: 20px; color: white;
        font-size: 12px; font-weight: 600; text-transform: uppercase;
        letter-spacing: 0.5px; white-space: nowrap;
    }}
    .finding-header .endpoint {{
        font-family: monospace; font-size: 13px; color: #4b5563;
        margin-top: 8px; word-break: break-all;
    }}
    .finding-header .owasp {{
        font-size: 12px; color: #6b7280; margin-top: 4px;
    }}

    .finding-body {{ padding: 24px; }}
    .section {{ margin-bottom: 20px; }}
    .section:last-child {{ margin-bottom: 0; }}
    .section-label {{
        font-size: 12px; font-weight: 700; text-transform: uppercase;
        letter-spacing: 0.5px; color: #6b7280; margin-bottom: 8px;
        display: flex; align-items: center; gap: 6px;
    }}
    .section-content {{ font-size: 14px; color: #374151; }}

    .plain-english {{
        background: #eff6ff; border-radius: 8px; padding: 16px;
        font-size: 14px; color: #1e40af;
    }}
    .impact-box {{
        background: #fef2f2; border-radius: 8px; padding: 16px;
        font-size: 14px; color: #991b1b;
    }}

    /* Code blocks */
    .code-block {{
        background: #1e293b; color: #e2e8f0; border-radius: 8px;
        padding: 16px; font-family: 'Courier New', monospace;
        font-size: 13px; overflow-x: auto; white-space: pre-wrap;
        word-break: break-word; line-height: 1.5;
    }}
    .code-block .method {{ color: #4ade80; font-weight: bold; }}
    .code-block .key {{ color: #60a5fa; }}
    .code-block .status-ok {{ color: #4ade80; }}

    .payload-box {{
        background: #fffbeb; border: 1px solid #fde68a;
        border-radius: 8px; padding: 14px; font-family: monospace;
        font-size: 13px; color: #92400e; word-break: break-all;
    }}

    .remediation {{
        background: #f0fdf4; border-radius: 8px; padding: 16px;
        font-size: 14px; color: #166534;
        border-left: 3px solid #16a34a;
    }}

    .evidence-stat {{
        display: inline-block; background: #f1f5f9; border-radius: 6px;
        padding: 6px 12px; margin: 4px 4px 4px 0; font-size: 13px;
        font-family: monospace;
    }}
    .evidence-stat .num {{ font-weight: 700; color: #1e3a8a; }}

    /* Footer */
    .footer {{
        text-align: center; padding: 30px 20px; color: #9ca3af;
        font-size: 13px;
    }}
</style>
</head>
<body>
    <div class="header">
        <h1>PentraAI Security Report</h1>
        <div class="subtitle">AI-Driven Autonomous Penetration Test</div>
        <div class="target">{html.escape(target)}</div>
    </div>

    <div class="summary-cards">
        <div class="card total"><div class="number">{total}</div><div class="label">Total</div></div>
        <div class="card critical"><div class="number">{critical}</div><div class="label">Critical</div></div>
        <div class="card high"><div class="number">{high}</div><div class="label">High</div></div>
        <div class="card medium"><div class="number">{medium}</div><div class="label">Medium</div></div>
    </div>

    <div class="container">
        <div class="exec-summary">
            <h2>Executive Summary</h2>
            <div class="section-content">{html.escape(summary)}</div>
            <div class="meta">
                <strong>Target:</strong> {html.escape(target)}<br>
                <strong>Scan date:</strong> {timestamp}<br>
                <strong>Tool:</strong> PentraAI v1.0 — Autonomous AI Penetration Testing Agent
            </div>
        </div>

        {findings_html}

        <div class="footer">
            Generated by PentraAI — AI-Driven Autonomous Web Penetration Testing<br>
            This report is for authorised security testing only.
        </div>
    </div>
    <script>location.search.indexOf('print=1')>-1 && (window.onload = window.print);</script>
</body>
</html>"""


def _render_finding(index: int, finding: dict) -> str:
    """Render one finding as an HTML card."""

    vuln_name = finding.get("vulnerability", "Unknown Vulnerability")
    severity  = finding.get("severity", "info").lower()
    endpoint  = finding.get("endpoint", "unknown")
    owasp     = finding.get("owasp", "")
    reasoning = finding.get("ai_reasoning", "")
    evidence  = finding.get("evidence", {})
    remediation = finding.get("remediation", "")

    sev_color = SEVERITY_COLORS.get(severity, "#6b7280")

    # Determine vulnerability type for plain-English explanation
    vuln_lower = vuln_name.lower()
    explanation = None
    if "idor" in vuln_lower or "bola" in vuln_lower or "object level" in vuln_lower:
        explanation = VULN_EXPLANATIONS["idor"]
    elif "auth" in vuln_lower or "jwt" in vuln_lower:
        explanation = VULN_EXPLANATIONS["broken_auth"]
    elif "race" in vuln_lower or "toctou" in vuln_lower:
        explanation = VULN_EXPLANATIONS["race_condition"]
    elif "rate limit" in vuln_lower:
        explanation = VULN_EXPLANATIONS["missing_rate_limit"]

    # Build plain-English section
    plain_html = ""
    if explanation:
        plain_html = f"""
        <div class="section">
            <div class="section-label">What this means</div>
            <div class="plain-english">{html.escape(explanation['simple'])}</div>
        </div>
        <div class="section">
            <div class="section-label">Why it matters</div>
            <div class="impact-box">{html.escape(explanation['impact'])}</div>
        </div>
        """

    # Build payload/technique section
    payload_html = _render_payload(finding, evidence)

    # Build request/response section
    req_resp_html = _render_request_response(evidence)

    # Build evidence stats (for race conditions)
    stats_html = _render_evidence_stats(evidence)

    # AI reasoning
    reasoning_html = ""
    if reasoning:
        reasoning_html = f"""
        <div class="section">
            <div class="section-label">Why PentraAI flagged this</div>
            <div class="section-content">{html.escape(reasoning)}</div>
        </div>
        """

    # Remediation
    remediation_html = ""
    if remediation:
        remediation_html = f"""
        <div class="section">
            <div class="section-label">How to fix it</div>
            <div class="remediation">{html.escape(remediation)}</div>
        </div>
        """

    return f"""
    <div class="finding {severity}">
        <div class="finding-header">
            <div class="title-row">
                <h3>{index}. {html.escape(vuln_name)}</h3>
                <span class="severity-badge" style="background:{sev_color}">{html.escape(severity)}</span>
            </div>
            <div class="endpoint">{html.escape(endpoint)}</div>
            {f'<div class="owasp">{html.escape(owasp)}</div>' if owasp else ''}
        </div>
        <div class="finding-body">
            {plain_html}
            {stats_html}
            {payload_html}
            {req_resp_html}
            {reasoning_html}
            {remediation_html}
        </div>
    </div>
    """


def _render_payload(finding: dict, evidence: dict) -> str:
    """Show the payload or attack technique used."""

    # JWT alg=none attack
    if evidence.get("attack") == "alg=none" or "forged_header" in evidence:
        header = evidence.get("forged_header", {"alg": "none", "typ": "JWT"})
        return f"""
        <div class="section">
            <div class="section-label">Attack payload used</div>
            <div class="payload-box">
                <strong>Technique:</strong> JWT Algorithm Confusion (alg=none)<br><br>
                <strong>Forged token header:</strong><br>
                {html.escape(json.dumps(header))}<br><br>
                <strong>How it works:</strong> The token's signature algorithm was changed to "none",
                removing the cryptographic signature entirely. A vulnerable server accepts this
                unsigned token as valid.
            </div>
        </div>
        """

    # Race condition
    if "requests_sent" in evidence:
        sent = evidence.get("requests_sent", 30)
        return f"""
        <div class="section">
            <div class="section-label">Attack technique used</div>
            <div class="payload-box">
                <strong>Technique:</strong> Concurrent Request Flooding (Race Condition / TOCTOU)<br><br>
                <strong>Method:</strong> {html.escape(str(sent))} identical requests were sent to the
                endpoint simultaneously using HTTP/2 multiplexing.<br><br>
                <strong>How it works:</strong> The server checks a condition (such as available balance
                or coupon validity) and then acts on it. By sending many requests at the exact same
                moment, all of them pass the check before any single one updates the record.
            </div>
        </div>
        """

    # IDOR
    if "idor" in finding.get("vulnerability", "").lower() or "bola" in finding.get("vulnerability", "").lower():
        return f"""
        <div class="section">
            <div class="section-label">Attack technique used</div>
            <div class="payload-box">
                <strong>Technique:</strong> Insecure Direct Object Reference (IDOR / BOLA)<br><br>
                <strong>Method:</strong> User B's authentication token was used to request a resource
                that belongs to a different user.<br><br>
                <strong>How it works:</strong> The server returned another user's private data without
                checking whether the requesting user is authorised to access it.
            </div>
        </div>
        """

    return ""


def _render_request_response(evidence: dict) -> str:
    """Render the HTTP request and response in a readable code block."""

    html_parts = []

    # Request
    request = evidence.get("request", {})
    if request:
        method = request.get("method", "GET")
        url    = request.get("url", "")
        headers = request.get("headers", {})
        headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        req_text = f"{method} {url}\n{headers_str}"
        html_parts.append(f"""
        <div class="section">
            <div class="section-label">Request sent</div>
            <div class="code-block">{html.escape(req_text)}</div>
        </div>
        """)

    # Response
    response = evidence.get("response", {})
    if response:
        status = response.get("status", "")
        body   = response.get("body", "")
        if isinstance(body, (dict, list)):
            body = json.dumps(body, indent=2)
        body = str(body)[:800]
        resp_text = f"HTTP {status}\n\n{body}"
        html_parts.append(f"""
        <div class="section">
            <div class="section-label">Server response</div>
            <div class="code-block">{html.escape(resp_text)}</div>
        </div>
        """)

    # Sample responses for race conditions
    samples = evidence.get("sample_success_responses", [])
    if samples and not response:
        samples_text = "\n---\n".join(str(s)[:200] for s in samples[:3])
        html_parts.append(f"""
        <div class="section">
            <div class="section-label">Sample successful responses (proof of repeated success)</div>
            <div class="code-block">{html.escape(samples_text)}</div>
        </div>
        """)

    return "".join(html_parts)


def _render_evidence_stats(evidence: dict) -> str:
    """Render race condition statistics as visual stat badges."""

    if "requests_sent" not in evidence:
        return ""

    sent     = evidence.get("requests_sent", 0)
    success  = evidence.get("successful_responses", 0)
    failed   = evidence.get("failed_responses", 0)
    expected = evidence.get("expected_max_successes", 1)

    return f"""
    <div class="section">
        <div class="section-label">Evidence</div>
        <div>
            <span class="evidence-stat">Requests sent: <span class="num">{sent}</span></span>
            <span class="evidence-stat">Succeeded: <span class="num">{success}</span></span>
            <span class="evidence-stat">Failed: <span class="num">{failed}</span></span>
            <span class="evidence-stat">Should have succeeded: <span class="num">{expected}</span></span>
        </div>
        <div class="section-content" style="margin-top:10px">
            <strong>{success} out of {sent}</strong> requests succeeded when only
            <strong>{expected}</strong> should have. This {success - expected}-request gap proves
            the vulnerability.
        </div>
    </div>
    """