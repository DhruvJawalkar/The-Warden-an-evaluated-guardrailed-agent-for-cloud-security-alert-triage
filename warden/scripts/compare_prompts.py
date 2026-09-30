"""Compare prompt variants over replicated runs (hand-read helper, NOT the week-4 harness).

    python scripts/compare_prompts.py v1=runs,runs/exp/v1_a,runs/exp/v1_b v2=runs/exp/v2_a,runs/exp/v2_b

Each argument is LABEL=dir[,dir...]; every dir is one full replicate of the 20 incidents.
Metrics per run: verdict correct, required-evidence recall, principal coverage (share of
principals_involved that appear in any tool-call argument), tool calls, cost.
"""
import glob
import json
import os
import sys
from collections import defaultdict

DS = os.environ.get("WARDEN_DATASET", "datasets/v1")
key = {}
with open(os.path.join(DS, "incidents.jsonl"), encoding="utf-8") as fh:
    for line in fh:
        rec = json.loads(line)
        key[rec["incident_id"]] = rec


def score(run):
    gt = key[run["incident_id"]]["ground_truth"]
    v = run["final_verdict"] or {}
    need = set(gt["required_evidence_event_ids"])
    args = [c["arguments"] for s in run["steps"] for c in s["tool_calls"]]
    seen = {a.get("principal_name") or a.get("name") for a in args}
    seen |= {p for a in args for p in [a.get("contains")] if p}
    who = gt["principals_involved"]
    return {
        "ok": v.get("verdict") == gt["verdict"],
        "recall": len(need & set(v.get("evidence_event_ids", []))) / max(1, len(need)),
        "princ": sum(1 for p in who if p in seen) / max(1, len(who)),
        "calls": len(run["trajectory"]),
        "cost": run["totals"]["cost_usd"],
        "done": run["stop_cause"] == "verdict_submitted",
    }


def load(dirs):
    reps = []
    for d in dirs:
        runs = {}
        for path in sorted(glob.glob(os.path.join(d, "*.json")), key=os.path.getmtime):
            r = json.load(open(path, encoding="utf-8"))
            runs[r["incident_id"]] = score(r)
        reps.append(runs)
    return reps


variants = {}
for arg in sys.argv[1:]:
    label, dirs = arg.split("=", 1)
    variants[label] = load(dirs.split(","))

EXCLUDE = set(filter(None, os.environ.get("EXCLUDE", "").split(",")))  # e.g. EXCLUDE=WRD-0006,WRD-0008
tiers = defaultdict(list)
for iid, rec in key.items():
    if iid not in EXCLUDE:
        tiers[rec["tier"]].append(iid)
tiers["ALL"] = sorted(set(key) - EXCLUDE)


def mean(xs):
    xs = list(xs)
    return sum(xs) / len(xs) if xs else float("nan")


print("%-6s %-5s %-4s %7s %8s %7s %6s %6s" % ("var", "tier", "reps", "verdict", "recall", "princ",
                                             "calls", "cost"))
for label, reps in variants.items():
    for tier in ("easy", "noisy", "hard", "ALL"):
        ids = tiers[tier]
        cells = [r[i] for r in reps for i in ids if i in r]
        print("%-6s %-5s %-4d %6.0f%% %7.0f%% %6.0f%% %6.1f %6.3f" % (
            label, tier, len(reps), 100 * mean(c["ok"] for c in cells),
            100 * mean(c["recall"] for c in cells), 100 * mean(c["princ"] for c in cells),
            mean(c["calls"] for c in cells), mean(c["cost"] for c in cells)))

print("\nper-incident mean recall / verdict-correct rate (rows = incident, cols = variant)")
labels = list(variants)
print("%-9s %-6s " % ("incident", "tier") + "  ".join("%-16s" % l for l in labels))
for iid in sorted(key):
    cols = []
    for l in labels:
        cells = [r[iid] for r in variants[l] if iid in r]
        cols.append("%3.0f%% / %d of %d ok" % (100 * mean(c["recall"] for c in cells),
                                              sum(c["ok"] for c in cells), len(cells)))
    print("%-9s %-6s " % (iid, key[iid]["tier"]) + "  ".join("%-16s" % c for c in cols))
