#!/usr/bin/env python3
"""
compare_nuclei.py — compare Nuclei's findings against PentraAI's on the same targets.

Reads:
  results/{target}_nuclei.json     — Nuclei's -je (json-export) output (JSON array)
  results/{target}_findings.csv    — PentraAI's reviewed findings (from the main benchmark)

Writes:
  results/nuclei_comparison.md

Usage:
  python compare_nuclei.py                 # both targets
  python compare_nuclei.py --target crapi  # one target
"""
import argparse
import csv
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "results")

TARGETS = ["juiceshop", "crapi"]

# PentraAI's five target vulnerability classes -> keywords used to tag a Nuclei
# finding as "in PentraAI's scope" vs "outside it" (generic CVE/exposure/misconfig).
INSCOPE_HINTS = {
    "idor":           ["idor", "bola", "object", "authoriz"],
    "broken_auth":    ["jwt", "auth-bypass", "default-login", "weak-cred", "token"],
    "ssrf":           ["ssrf"],
    "bfla":           ["bfla", "privilege", "function-level"],
    "race_condition": ["race"],
}


def load_nuclei(target):
    path = os.path.join(RESULTS_DIR, f"{target}_nuclei.json")
    if not os.path.exists(path):
        print(f"  (skip {target}: no {path} — run nuclei first)")
        return []
    with open(path, encoding="utf-8") as f:
        raw = f.read().strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        return data
    except json.JSONDecodeError:
        # tolerate JSONL (one JSON object per line) as a fallback
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items


def load_pentraai_csv(target):
    path = os.path.join(RESULTS_DIR, f"{target}_findings.csv")
    if not os.path.exists(path):
        print(f"  (skip {target} PentraAI side: no {path})")
        return []
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        return list(csv.DictReader(f))


def classify_nuclei_finding(item):
    """Return the PentraAI module this Nuclei finding overlaps with, or None
    if it's outside PentraAI's five target classes (generic CVE/exposure/etc)."""
    info = item.get("info", {}) or {}
    haystack = " ".join([
        item.get("template-id", "") or item.get("templateID", ""),
        info.get("name", ""),
        " ".join(info.get("tags", []) if isinstance(info.get("tags"), list) else [info.get("tags", "")]),
    ]).lower()
    for module, hints in INSCOPE_HINTS.items():
        if any(h in haystack for h in hints):
            return module
    return None


def summarize_target(target):
    nuclei_items = load_nuclei(target)
    pentraai_rows = load_pentraai_csv(target)

    pentraai_tp = [r for r in pentraai_rows if (r.get("verdict (TP/FP)") or "").strip().upper() == "TP"]

    nuclei_by_severity = defaultdict(int)
    nuclei_inscope = []
    nuclei_outscope = []
    for item in nuclei_items:
        info = item.get("info", {}) or {}
        sev = (info.get("severity") or "unknown").lower()
        nuclei_by_severity[sev] += 1
        mod = classify_nuclei_finding(item)
        entry = {
            "template": item.get("template-id", item.get("templateID", "?")),
            "name": info.get("name", "?"),
            "severity": sev,
            "matched_at": item.get("matched-at", item.get("host", "?")),
        }
        if mod:
            entry["module"] = mod
            nuclei_inscope.append(entry)
        else:
            nuclei_outscope.append(entry)

    return {
        "target": target,
        "nuclei_total": len(nuclei_items),
        "nuclei_by_severity": dict(nuclei_by_severity),
        "nuclei_inscope": nuclei_inscope,
        "nuclei_outscope": nuclei_outscope,
        "pentraai_tp": pentraai_tp,
    }


def render_report(summaries):
    out = []
    out.append("# PentraAI vs Nuclei — Comparison Results\n")

    out.append("## Summary\n")
    out.append("| Target | Nuclei findings | Nuclei in PentraAI's scope | PentraAI TPs |")
    out.append("|---|---|---|---|")
    for s in summaries:
        out.append(f"| {s['target']} | {s['nuclei_total']} | {len(s['nuclei_inscope'])} | {len(s['pentraai_tp'])} |")
    out.append("")

    for s in summaries:
        out.append(f"## {s['target']}\n")

        out.append("### Nuclei findings by severity")
        if s["nuclei_by_severity"]:
            out.append("| Severity | Count |")
            out.append("|---|---|")
            for sev, cnt in sorted(s["nuclei_by_severity"].items()):
                out.append(f"| {sev} | {cnt} |")
        else:
            out.append("_(no Nuclei results loaded — run nuclei first)_")
        out.append("")

        out.append("### Nuclei findings that overlap PentraAI's target classes (IDOR/auth/SSRF/BFLA/race)")
        if s["nuclei_inscope"]:
            out.append("| Template | Name | Severity | Overlaps module |")
            out.append("|---|---|---|---|")
            for e in s["nuclei_inscope"]:
                out.append(f"| {e['template']} | {e['name']} | {e['severity']} | {e['module']} |")
        else:
            out.append("_None — no Nuclei finding matched PentraAI's authorization/auth/SSRF/BFLA/race classes._")
        out.append("")

        out.append("### Nuclei findings outside PentraAI's scope (generic CVE/exposure/misconfig/tech)")
        if s["nuclei_outscope"]:
            out.append("| Template | Name | Severity |")
            out.append("|---|---|---|")
            for e in s["nuclei_outscope"][:30]:
                out.append(f"| {e['template']} | {e['name']} | {e['severity']} |")
            if len(s["nuclei_outscope"]) > 30:
                out.append(f"| … | *(+{len(s['nuclei_outscope']) - 30} more)* | |")
        else:
            out.append("_None._")
        out.append("")

        out.append("### PentraAI true positives (from the main benchmark)")
        if s["pentraai_tp"]:
            out.append("| Module | Vulnerability | gt_id |")
            out.append("|---|---|---|")
            for r in s["pentraai_tp"]:
                out.append(f"| {r.get('module','')} | {r.get('vulnerability','')} | {r.get('gt_id (for TP)','')} |")
        else:
            out.append("_None loaded — check results/{target}_findings.csv exists and is marked._")
        out.append("")

    out.append("## Interpretation\n")
    out.append(
        "Nuclei's findings (if any landed in PentraAI's scope column above) are almost always "
        "coincidental — e.g. a default-login template matching an exposed panel — rather than the "
        "authenticated, multi-step logic PentraAI performs (harvesting a victim's object id, forging "
        "a JWT, comparing two authenticated sessions' responses). Conversely, PentraAI does not "
        "fingerprint CVEs or check for outdated dependencies, which is Nuclei's core strength. The "
        "two tools cover different, complementary parts of a real assessment's scope."
    )

    return "\n".join(out)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target")
    p.add_argument("--all", action="store_true", default=True)
    args = p.parse_args()

    targets = [args.target] if args.target else TARGETS
    summaries = [summarize_target(t) for t in targets]

    report = render_report(summaries)
    out_path = os.path.join(RESULTS_DIR, "nuclei_comparison.md")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(report)
    print(f"\n-> wrote {out_path}")


if __name__ == "__main__":
    main()