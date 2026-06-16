"""
report.py — Phase 5: Report Generation
The LLM takes all confirmed findings and writes a structured,
developer-focused vulnerability report with evidence and fixes.
"""

import json
from llm import call_llm


async def generate_report(findings: list[dict], recon_data: dict) -> dict:
    """
    Generate the final pentest report from all confirmed findings.

    Args:
        findings:   List of confirmed vulnerability findings
        recon_data: Recon context (target URL, tech stack etc.)

    Returns:
        Structured report dict with summary and detailed findings
    """
    if not findings:
        return _empty_report(recon_data)

    # Generate executive summary
    summary = _generate_summary(findings, recon_data)

    # Enrich each finding with remediation advice
    enriched = []
    for finding in findings:
        enriched.append(_enrich_finding(finding, recon_data))

    return {
        "target":          recon_data.get("target_url", "unknown"),
        "tech_stack":      recon_data.get("tech_stack", {}),
        "total_findings":  len(findings),
        "critical":        sum(1 for f in findings if f.get("severity") == "critical"),
        "high":            sum(1 for f in findings if f.get("severity") == "high"),
        "medium":          sum(1 for f in findings if f.get("severity") == "medium"),
        "low":             sum(1 for f in findings if f.get("severity") == "low"),
        "executive_summary": summary,
        "findings":        enriched,
    }


def _generate_summary(findings: list[dict], recon_data: dict) -> str:
    """Ask the LLM to write a plain-English executive summary."""

    findings_text = "\n".join(
        f"- {f.get('vulnerability', 'Unknown')} at {f.get('endpoint', 'unknown')} "
        f"(severity: {f.get('severity', 'unknown')})"
        for f in findings
    )

    prompt = f"""You are a security consultant writing an executive summary for a pentest report.

Target: {recon_data.get("target_url")}
Tech stack: {recon_data.get("tech_stack", {})}

Confirmed findings:
{findings_text}

Write a 3-sentence executive summary for developers. Be direct and specific.
Mention the most critical finding first. End with the immediate action required.
Do not use bullet points. Plain paragraph only."""

    try:
        return call_llm(prompt)
    except Exception:
        return (
            f"The scan identified {len(findings)} vulnerabilities on the target application. "
            "Immediate remediation is recommended for all critical and high severity findings. "
            "Please review each finding below for specific evidence and fix guidance."
        )


def _enrich_finding(finding: dict, recon_data: dict) -> dict:
    """Ask the LLM to write a remediation recommendation for one finding."""

    tech = recon_data.get("tech_stack", {})
    tech_str = ", ".join(f"{k}: {v}" for k, v in tech.items()) or "unknown"

    prompt = f"""You are a security engineer writing remediation advice for a developer.

Vulnerability: {finding.get("vulnerability")}
Endpoint: {finding.get("endpoint")}
Evidence: {finding.get("evidence", "See request/response below")}
Tech stack: {tech_str}

Write a specific, actionable fix in 2-3 sentences.
Name the exact code pattern or configuration to change.
Be specific to the tech stack if known.
No bullet points. Plain text only."""

    try:
        remediation = call_llm(prompt)
    except Exception:
        remediation = "Implement proper authorisation checks. Verify the requesting user owns the resource before returning data."

    return {**finding, "remediation": remediation}


def _empty_report(recon_data: dict) -> dict:
    """Return a clean report when no vulnerabilities were found."""
    return {
        "target":            recon_data.get("target_url", "unknown"),
        "tech_stack":        recon_data.get("tech_stack", {}),
        "total_findings":    0,
        "critical":          0,
        "high":              0,
        "medium":            0,
        "low":               0,
        "executive_summary": "No vulnerabilities were detected during this scan. This does not guarantee the application is secure — manual testing is always recommended.",
        "findings":          [],
    }
