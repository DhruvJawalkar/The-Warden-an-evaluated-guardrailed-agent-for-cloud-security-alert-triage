"""Hand-read helper for week 1 (NOT the week-4 harness): one row per run vs the answer key.

    python scripts/summarize_runs.py [runs_dir] [dataset_dir]
"""
import glob
import json
import os
import sys

runs_dir = sys.argv[1] if len(sys.argv) > 1 else "runs"
ds = sys.argv[2] if len(sys.argv) > 2 else "datasets/v1"
key = {}
with open(os.path.join(ds, "incidents.jsonl"), encoding="utf-8") as fh:
    for line in fh:
        rec = json.loads(line)
        key[rec["incident_id"]] = rec

latest = {}
for path in sorted(glob.glob(os.path.join(runs_dir, "*.json")), key=os.path.getmtime):
    r = json.load(open(path, encoding="utf-8"))
    latest[r["incident_id"]] = r

hdr = "%-9s %-6s %-22s %-9s %-4s %-4s %-3s %-8s %-8s %-9s %-4s %s"
print(hdr % ("incident", "tier", "scenario", "stop", "step", "min", "ev%", "verdict", "truth",
             "describe", "cost", "biggest_tool_result(chars)"))
tot = {}
for iid in sorted(latest):
    r, k = latest[iid], key[iid]
    gt = k["ground_truth"]
    v = r["final_verdict"] or {}
    need = set(gt["required_evidence_event_ids"])
    cited = set(v.get("evidence_event_ids", []))
    ev = 100 * len(need & cited) // max(1, len(need))
    traj = r["trajectory"]
    principals = [c["arguments"].get("name") for s in r["steps"] for c in s["tool_calls"]
                  if c["name"] == "describe_principal"]
    mx = max((len(t["payload_preview"]) for s in r["steps"] for t in s["tool_results"]), default=0)
    ok = v.get("verdict") == gt["verdict"]
    t = tot.setdefault(k["tier"], [0, 0, 0, 0])
    t[0] += 1
    t[1] += ok
    t[2] += r["step_count"]
    t[3] += r["totals"]["cost_usd"]
    print(hdr % (iid, k["tier"], k["scenario"][:22], r["stop_cause"][:9], r["step_count"],
                 gt["min_steps"], ev, (v.get("verdict") or "-")[:8], gt["verdict"][:8],
                 "%d/%d" % (len(set(principals)), len(gt["principals_involved"])),
                 "%.3f" % r["totals"]["cost_usd"], mx))
print()
for tier, (n, ok, steps, cost) in tot.items():
    print("%-6s n=%d verdict_correct=%d/%d avg_steps=%.1f cost=$%.3f" % (tier, n, ok, n, steps / n, cost))
