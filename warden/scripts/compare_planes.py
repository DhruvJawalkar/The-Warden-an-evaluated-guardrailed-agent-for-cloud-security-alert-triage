"""Week-2 re-baseline: in-process vs MCP tool plane, same 20 incidents, one run per arm.

    python scripts/compare_planes.py [runs/w2-inproc] [runs/w2-mcp] [datasets/v1]

Hand-read helper (NOT the week-4 harness). n=1 per arm per incident, so per-incident differences are
noise; only aggregates, and any tool-error or crash differences, are worth reading.
"""
import glob
import json
import os
import sys

a_dir = sys.argv[1] if len(sys.argv) > 1 else "runs/w2-inproc"
b_dir = sys.argv[2] if len(sys.argv) > 2 else "runs/w2-mcp"
ds = sys.argv[3] if len(sys.argv) > 3 else "datasets/v1"

key = {}
with open(os.path.join(ds, "incidents.jsonl"), encoding="utf-8") as fh:
    for line in fh:
        rec = json.loads(line)
        key[rec["incident_id"]] = rec


def load(d):
    out = {}
    for p in sorted(glob.glob(os.path.join(d, "*.json")), key=os.path.getmtime):
        r = json.load(open(p, encoding="utf-8"))
        out[r["incident_id"]] = r
    return out


def row(r, k):
    gt = k["ground_truth"]
    v = r["final_verdict"] or {}
    need = set(gt["required_evidence_event_ids"])
    cited = set(v.get("evidence_event_ids", []))
    calls = sum(len(s["tool_calls"]) for s in r["steps"])
    errs = sum(1 for s in r["steps"] for t in s["tool_results"] if t["is_error"])
    return {"ok": v.get("verdict") == gt["verdict"], "ev": len(need & cited) / max(1, len(need)),
            "calls": calls, "turns": r["step_count"], "cost": r["totals"]["cost_usd"], "errs": errs,
            "stop": r["stop_cause"], "lat": sum(s["latency_ms"] for s in r["steps"]),
            "tool_ms": sum(t.get("latency_ms", 0) or 0 for s in r["steps"] for t in s["tool_results"])}


A, B = load(a_dir), load(b_dir)
ids = sorted(set(A) & set(B))
print("incident  tier   | inproc: ok ev%% calls err stop            | mcp: ok ev%% calls err stop")
agg = {"A": [], "B": []}
for i in ids:
    ra, rb = row(A[i], key[i]), row(B[i], key[i])
    agg["A"].append(ra)
    agg["B"].append(rb)
    print("%s %-6s | %-3s %3d %3d %3d %-16s | %-3s %3d %3d %3d %s" % (
        i, key[i]["tier"], "Y" if ra["ok"] else "n", 100 * ra["ev"], ra["calls"], ra["errs"], ra["stop"][:16],
        "Y" if rb["ok"] else "n", 100 * rb["ev"], rb["calls"], rb["errs"], rb["stop"]))


def mean(rows, k):
    return sum(r[k] for r in rows) / max(1, len(rows))


print("\nn=%d incidents in both arms (inproc has %d, mcp has %d)" % (len(ids), len(A), len(B)))
print("%-22s %10s %10s" % ("", "inproc", "mcp"))
for label, k, fmt in [("verdict correct", "ok", "%.0f%%"), ("evidence recall", "ev", "%.0f%%"),
                      ("tool calls / run", "calls", "%.1f"), ("model turns / run", "turns", "%.1f"),
                      ("tool errors / run", "errs", "%.2f"), ("cost / run ($)", "cost", "%.4f"),
                      ("model latency ms/run", "lat", "%.0f"), ("tool latency ms/run", "tool_ms", "%.0f")]:
    scale = 100 if fmt.endswith("%%") else 1
    print("%-22s %10s %10s" % (label, fmt % (scale * mean(agg["A"], k)), fmt % (scale * mean(agg["B"], k))))
for arm, rows in (("inproc", agg["A"]), ("mcp", agg["B"])):
    stops = {}
    for r in rows:
        stops[r["stop"]] = stops.get(r["stop"], 0) + 1
    print("stop causes %-7s %s" % (arm, stops))
same_verdict = sum(1 for i in ids if (A[i]["final_verdict"] or {}).get("verdict") == (B[i]["final_verdict"] or {}).get("verdict"))
print("same verdict in both arms: %d/%d" % (same_verdict, len(ids)))
