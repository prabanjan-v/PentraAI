#!/usr/bin/env python3
"""
benchmark.py — PentraAI benchmark harness.
 
Two modes:
 
  RUN:    python benchmark.py run --target juiceshop
          python benchmark.py run --target crapi
          python benchmark.py run --all
            -> Starts a scan on the RUNNING PentraAI API, streams findings,
               tags each finding with the module that produced it, times the
               scan, and writes:
                 results/<target>_raw.json      (all SSE events + final report)
                 results/<target>_findings.csv  (one row per finding; you fill
                                                 in the 'verdict' and 'gt_id' cols)
 
  SCORE:  python benchmark.py score --target juiceshop
          python benchmark.py score --all
            -> Reads your reviewed results/<target>_findings.csv + ground_truth.json
               and computes detection rate, precision, false-positive rate, and a
               per-module breakdown. Writes results/<target>_scores.md.
 
Requires only 'httpx' (already in PentraAI's requirements). The PentraAI API must
be running (uvicorn main:app --port 8000) and the targets must be reachable.
"""
 
import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
 
try:
    import httpx
except ImportError:
    sys.exit("httpx is required. Install with: pip install httpx")
 
HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)
 
 
def load_json(name):
    with open(os.path.join(HERE, name), "r", encoding="utf-8") as f:
        return json.load(f)
 
 
def load_targets():
    path = os.path.join(HERE, "targets.json")
    if not os.path.exists(path):
        sys.exit("targets.json not found. Copy targets.example.json to targets.json "
                 "and fill in URLs / credentials / tokens.")
    return load_json("targets.json")
 
 
def _finding_name(f):
    """Modules store the vuln name under 'vulnerability'; fall back gracefully."""
    for k in ("vulnerability", "title", "name", "type", "vuln"):
        v = f.get(k)
        if v:
            return str(v)
    return "(no title)"
 
 
def _short(text, n=160):
    if not text:
        return ""
    text = " ".join(str(text).split())
    return text[:n] + ("…" if len(text) > n else "")
 
 
def _extract_findings(events):
    """Turn a raw SSE event list into module-tagged findings."""
    findings = []
    current_module = "unknown"
    for evt in events:
        etype = evt.get("type")
        if etype == "progress" and evt.get("phase") == "testing":
            mod = (evt.get("data") or {}).get("module")
            if mod:
                current_module = mod
        elif etype == "finding":
            f = dict(evt)
            f["module"] = current_module
            findings.append(f)
    return findings
 
 
def _write_findings_csv(name, findings):
    csv_path = os.path.join(RESULTS_DIR, f"{name}_findings.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["idx", "module", "severity", "vulnerability", "endpoint",
                    "evidence", "verdict (TP/FP)", "gt_id (for TP)", "reviewer notes"])
        for i, fd in enumerate(findings, 1):
            w.writerow([i, fd.get("module", ""), fd.get("severity", ""),
                        _finding_name(fd), fd.get("endpoint", ""),
                        _short(fd.get("evidence") or fd.get("reasoning") or ""),
                        "", "", ""])
    return csv_path
 
 
# ---------------------------------------------------------------------------
# RUN
# ---------------------------------------------------------------------------
 
def run_target(name, cfg, api_base):
    print(f"\n=== Scanning '{name}'  ({cfg['target_url']}) ===")
    scan_req = {
        "target_url":      cfg["target_url"],
        "modules":         cfg.get("modules", ["idor", "broken_auth", "ssrf", "bfla", "race_condition"]),
        "user_a_email":    cfg.get("user_a_email", ""),
        "user_a_password": cfg.get("user_a_password", ""),
        "user_b_email":    cfg.get("user_b_email", ""),
        "user_b_password": cfg.get("user_b_password", ""),
        "user_a_token":    cfg.get("user_a_token", ""),
        "user_b_token":    cfg.get("user_b_token", ""),
    }
 
    t0 = time.time()
    with httpx.Client(base_url=api_base, timeout=30.0) as client:
        r = client.post("/scan", json=scan_req)
        r.raise_for_status()
        scan_id = r.json()["scan_id"]
        stream_path = r.json().get("stream_url", f"/scan/{scan_id}/stream")
    print(f"  scan_id = {scan_id}")
 
    events = []
    findings = []
    current_module = "unknown"
 
    # Stream findings. No read timeout — LLM phases can be slow.
    with httpx.Client(base_url=api_base, timeout=httpx.Timeout(30.0, read=None)) as client:
        with client.stream("GET", stream_path) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line or not line.startswith("data: "):
                    continue
                try:
                    evt = json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
                events.append(evt)
                etype = evt.get("type")
 
                if etype == "progress" and evt.get("phase") == "testing":
                    mod = (evt.get("data") or {}).get("module")
                    if mod:
                        current_module = mod
                    print(f"  [testing] {current_module}")
 
                elif etype == "finding":
                    f = dict(evt)
                    f["module"] = current_module
                    findings.append(f)
                    print(f"    FINDING [{current_module}] {f.get('severity','?'):8} "
                          f"{_finding_name(f)}")
 
                elif etype in ("complete", "done"):
                    break
                elif etype == "error":
                    print(f"  !! server error: {evt.get('message')}")
                    break
 
    elapsed = round(time.time() - t0, 1)
 
    # Pull the consolidated final report (includes remediation).
    final_report = {}
    try:
        with httpx.Client(base_url=api_base, timeout=30.0) as client:
            fr = client.get(f"/scan/{scan_id}")
            if fr.status_code == 200:
                final_report = fr.json().get("results", {})
    except Exception:
        pass
 
    # Write raw json
    raw_path = os.path.join(RESULTS_DIR, f"{name}_raw.json")
    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump({
            "target": name,
            "target_url": cfg["target_url"],
            "scan_id": scan_id,
            "elapsed_seconds": elapsed,
            "run_at": datetime.now(timezone.utc).isoformat(),
            "events": events,
            "final_report": final_report,
        }, f, indent=2)
 
    # Write findings CSV (verdict + gt_id left blank for manual review)
    csv_path = _write_findings_csv(name, findings)
 
    print(f"  -> {len(findings)} finding(s) in {elapsed}s")
    print(f"  -> wrote {csv_path}")
    print(f"  -> wrote {raw_path}")
    print(f"  NEXT: open the CSV, mark each row TP or FP, and put the matching "
          f"ground-truth id (e.g. {name.split('_')[0]}-idor-1) in gt_id for TP rows.")
    return {"target": name, "findings": len(findings), "elapsed": elapsed}
 
 
# ---------------------------------------------------------------------------
# SCORE
# ---------------------------------------------------------------------------
 
def score_target(name, ground_truth):
    csv_path = os.path.join(RESULTS_DIR, f"{name}_findings.csv")
    if not os.path.exists(csv_path):
        print(f"  (skip {name}: no reviewed CSV at {csv_path})")
        return None
    if name not in ground_truth:
        print(f"  (skip {name}: no ground_truth entry)")
        return None
 
    gt_items = ground_truth[name]["in_scope_vulns"]
    gt_ids = {g["id"] for g in gt_items}
    gt_by_module = {}
    for g in gt_items:
        gt_by_module.setdefault(g["module"], []).append(g["id"])
 
    rows = []
    with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as f:
        for row in csv.DictReader(f):
            rows.append(row)
 
    def verdict(row):
        return (row.get("verdict (TP/FP)") or "").strip().upper()
 
    tp_rows = [r for r in rows if verdict(r) == "TP"]
    fp_rows = [r for r in rows if verdict(r) == "FP"]
    unmarked = [r for r in rows if verdict(r) not in ("TP", "FP")]
 
    detected_gt = {(r.get("gt_id (for TP)") or "").strip()
                   for r in tp_rows if (r.get("gt_id (for TP)") or "").strip()}
    detected_gt &= gt_ids  # ignore typos not in ground truth
    missed_gt = gt_ids - detected_gt
 
    tp, fp = len(tp_rows), len(fp_rows)
    total_findings = len(rows)
    n_scope = len(gt_ids)
 
    detection_rate = (len(detected_gt) / n_scope) if n_scope else 0.0
    precision = (tp / (tp + fp)) if (tp + fp) else 0.0
    fp_rate = (fp / total_findings) if total_findings else 0.0
 
    # Per-module table
    per_module = {}
    modules = sorted(set(list(gt_by_module.keys()) + [r.get("module", "") for r in rows]))
    for m in modules:
        m_gt = set(gt_by_module.get(m, []))
        m_detected = {gid for gid in detected_gt if gid in m_gt}
        m_tp = len([r for r in tp_rows if r.get("module") == m])
        m_fp = len([r for r in fp_rows if r.get("module") == m])
        per_module[m] = {
            "in_scope": len(m_gt),
            "detected": len(m_detected),
            "tp": m_tp,
            "fp": m_fp,
            "missed": sorted(m_gt - m_detected),
        }
 
    # Write markdown
    out = []
    out.append(f"## Benchmark scores — {ground_truth[name]['display_name']}\n")
    out.append(f"_Scored {datetime.now(timezone.utc).strftime('%Y-%m-%d')} from `{name}_findings.csv`._\n")
    if unmarked:
        out.append(f"> ⚠️ {len(unmarked)} finding(s) not yet marked TP/FP — score is incomplete.\n")
    out.append("| Metric | Value |")
    out.append("|---|---|")
    out.append(f"| In-scope known vulns | {n_scope} |")
    out.append(f"| Detected (unique) | {len(detected_gt)} |")
    out.append(f"| True positives (findings) | {tp} |")
    out.append(f"| False positives (findings) | {fp} |")
    out.append(f"| **Detection rate** (detected / in-scope) | **{detection_rate:.0%}** |")
    out.append(f"| **Precision** (TP / (TP+FP)) | **{precision:.0%}** |")
    out.append(f"| **False-positive rate** (FP / all findings) | **{fp_rate:.0%}** |")
    out.append("")
    out.append("### Per-module breakdown\n")
    out.append("| Module | In-scope | Detected | TP | FP | Missed (FN) |")
    out.append("|---|---|---|---|---|---|")
    for m in modules:
        d = per_module[m]
        out.append(f"| {m} | {d['in_scope']} | {d['detected']} | {d['tp']} | "
                   f"{d['fp']} | {', '.join(d['missed']) or '—'} |")
    out.append("")
    md = "\n".join(out)
 
    scores_path = os.path.join(RESULTS_DIR, f"{name}_scores.md")
    with open(scores_path, "w", encoding="utf-8") as f:
        f.write(md)
 
    print(md)
    print(f"  -> wrote {scores_path}")
    return {
        "target": name, "detection_rate": detection_rate,
        "precision": precision, "fp_rate": fp_rate,
        "tp": tp, "fp": fp, "in_scope": n_scope, "detected": len(detected_gt),
    }
 
 
# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
 
def main():
    p = argparse.ArgumentParser(description="PentraAI benchmark harness")
    sub = p.add_subparsers(dest="cmd", required=True)
 
    pr = sub.add_parser("run", help="run a scan and collect findings")
    pr.add_argument("--target")
    pr.add_argument("--all", action="store_true")
 
    ps = sub.add_parser("score", help="score reviewed findings against ground truth")
    ps.add_argument("--target")
    ps.add_argument("--all", action="store_true")
 
    pb = sub.add_parser("rebuild",
                        help="regenerate findings CSV from an existing *_raw.json (no re-scan)")
    pb.add_argument("--target")
    pb.add_argument("--all", action="store_true")
 
    args = p.parse_args()
 
    if args.cmd == "rebuild":
        import glob
        if args.all:
            raws = sorted(glob.glob(os.path.join(RESULTS_DIR, "*_raw.json")))
            names = [os.path.basename(x)[:-len("_raw.json")] for x in raws]
        else:
            names = [args.target]
        if not names or names == [None]:
            sys.exit("Specify --target <name> or --all")
        for n in names:
            raw_path = os.path.join(RESULTS_DIR, f"{n}_raw.json")
            if not os.path.exists(raw_path):
                print(f"  (skip {n}: no {raw_path})"); continue
            with open(raw_path, encoding="utf-8") as f:
                data = json.load(f)
            findings = _extract_findings(data.get("events", []))
            csv_path = _write_findings_csv(n, findings)
            print(f"  {n}: rebuilt {len(findings)} finding(s) -> {csv_path}")
        return
 
    if args.cmd == "run":
        cfg = load_targets()
        api_base = cfg.get("api_base", "http://localhost:8000")
        targets = cfg["targets"]
        names = list(targets) if args.all else [args.target]
        if not names or names == [None]:
            sys.exit("Specify --target <name> or --all")
        summary = []
        for n in names:
            if n not in targets:
                print(f"  (unknown target '{n}')"); continue
            try:
                summary.append(run_target(n, targets[n], api_base))
            except httpx.HTTPError as e:
                print(f"  !! HTTP error scanning {n}: {e}")
        print("\n=== run summary ===")
        for s in summary:
            print(f"  {s['target']:12} {s['findings']:>3} findings  {s['elapsed']:>6}s")
 
    elif args.cmd == "score":
        gt = load_json("ground_truth.json")
        gt = {k: v for k, v in gt.items() if not k.startswith("_")}
        names = list(gt) if args.all else [args.target]
        if not names or names == [None]:
            sys.exit("Specify --target <name> or --all")
        results = []
        for n in names:
            res = score_target(n, gt)
            if res:
                results.append(res)
        if len(results) > 1:
            print("\n=== overall ===")
            for r in results:
                print(f"  {r['target']:12} detection {r['detection_rate']:.0%}  "
                      f"precision {r['precision']:.0%}  fp-rate {r['fp_rate']:.0%}")
 
 
if __name__ == "__main__":
    main()