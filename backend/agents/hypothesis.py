"""
hypothesis.py — Phase 2: Vulnerability Hypothesis
The LLM reads the recon data and decides which vulnerability
modules to run, in what order, and why.

This is what separates PentraAI from rule-based scanners.
A rule-based scanner tests everything blindly.
This LLM reads the app and makes an intelligent decision.
"""

import json
from llm import call_llm


async def run_hypothesis(recon_data: dict) -> list[dict]:
    """
    Ask the LLM to analyse recon findings and produce a test plan.

    Args:
        recon_data: Everything collected in Phase 1 (recon)

    Returns:
        List of modules to run, ordered by priority.
        Each item has: module, priority, reason, endpoints, confidence
    """
    prompt = _build_prompt(recon_data)

    try:
        raw = call_llm(prompt, expect_json=True)
        data = json.loads(raw)
        modules = data.get("test_plan", [])

        # Sort by priority (1 = highest)
        modules.sort(key=lambda x: x.get("priority", 99))
        return modules

    except Exception as e:
        # If LLM fails, fall back to testing all modules
        print(f"Hypothesis LLM failed: {e}. Using default plan.")
        return _default_plan(recon_data)


def _build_prompt(recon_data: dict) -> str:
    """Build the hypothesis prompt from recon data."""

    endpoints = "\n".join(
        f"  - {e}" for e in recon_data.get("alive_endpoints", [])
    ) or "  - None found"

    id_patterns = "\n".join(
        f"  - {p['template']} (type: {p['type']}, example: {p.get('example','')})"
        for p in recon_data.get("id_patterns", [])
    ) or "  - None detected"

    tech = recon_data.get("tech_stack", {})
    tech_str = "\n".join(f"  - {k}: {v}" for k, v in tech.items()) or "  - Unknown"

    forms = recon_data.get("forms", [])
    has_hidden = any(f.get("has_hidden") for f in forms)

    return f"""You are a senior penetration tester analysing reconnaissance data.
Based on the findings below, decide which vulnerability modules to run.

=== RECON FINDINGS ===

Target: {recon_data.get("target_url", "unknown")}

Tech stack detected:
{tech_str}

Live endpoints found:
{endpoints}

ID patterns detected (IDOR candidates):
{id_patterns}

GraphQL detected: {recon_data.get("graphql_found", "No")}
File upload found: {recon_data.get("file_upload", "No")}
API spec found: {recon_data.get("api_spec_found", False)}
Hidden form fields: {has_hidden}
Robots.txt paths: {recon_data.get("robots_paths", [])}

=== AVAILABLE MODULES ===
- idor          : Test cross-user object access (BOLA)
- broken_auth   : Test JWT weaknesses and OAuth misconfigs
- business_logic: Test workflow bypasses and logic flaws

=== YOUR TASK ===
Return ONLY a JSON object. No explanation outside the JSON.
Choose which modules to run based on evidence in the recon data.

{{
  "test_plan": [
    {{
      "module": "idor",
      "priority": 1,
      "reason": "why this module fits this target",
      "endpoints": ["/api/users/{{id}}", "/api/orders/{{id}}"],
      "confidence": "HIGH"
    }}
  ],
  "skip": [
    {{
      "module": "business_logic",
      "reason": "no transactional flow detected"
    }}
  ]
}}

Rules:
- Only include modules where recon evidence supports testing
- Priority 1 = test first, 3 = test last
- Confidence must be HIGH, MEDIUM, or LOW
- endpoints list should be specific URLs from recon, not generic
- If no ID patterns found, skip idor
- If no login/auth detected, skip broken_auth
- Always include at least 1 module
"""


def _default_plan(recon_data: dict) -> list[dict]:
    """
    Fallback plan if the LLM call fails.
    Runs all modules if there is evidence for them.
    """
    plan = []
    priority = 1

    if recon_data.get("id_patterns"):
        plan.append({
            "module":     "idor",
            "priority":   priority,
            "reason":     "ID patterns found during recon (default plan)",
            "endpoints":  [p["template"] for p in recon_data["id_patterns"][:3]],
            "confidence": "MEDIUM"
        })
        priority += 1

    plan.append({
        "module":     "broken_auth",
        "priority":   priority,
        "reason":     "Testing authentication by default",
        "endpoints":  [recon_data.get("target_url", "") + "/login"],
        "confidence": "MEDIUM"
    })
    priority += 1

    if recon_data.get("forms"):
        plan.append({
            "module":     "business_logic",
            "priority":   priority,
            "reason":     "Forms detected during recon (default plan)",
            "endpoints":  [f["action"] for f in recon_data["forms"][:2]],
            "confidence": "LOW"
        })

    return plan
