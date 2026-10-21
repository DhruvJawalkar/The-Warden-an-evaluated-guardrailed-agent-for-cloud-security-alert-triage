"""Toolset evaluation: what each tool costs, how often it fails, and whether it moves the verdict.

    python -m warden.evalkit.toolset runs/w2-mcp                     # run-record metrics
    python -m warden.evalkit.toolset runs/w2-mcp --lint w1           # + static schema lint (starts servers)
    python -m warden.evalkit.toolset runs/w2-mcp --lint full

Two kinds of evidence, kept apart on purpose:

  STATIC   lint_schemas: properties of the tool surface the model is offered, no run needed. Token
           cost of the schemas, undocumented parameters, thin descriptions.
  DYNAMIC  per_tool / evidence_funnel / runbook_use: read from saved RunRecords joined to the answer
           key. They describe what a model did with the tools in n runs; they do not prove a tool
           CAUSES a better verdict. That needs an arm without the tool (week 6 ablation).

Fields added in week 2.5 (`rendered_chars`, `event_ids`, `section_ids` per tool result) are absent from
older run files. Every metric that needs them reports n/a for those runs rather than guessing, and says
how many runs it could use.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
from collections import Counter, defaultdict

from warden.evalkit.stats import mean

LOG_TOOLS = ("search_logs", "get_events")
RUNBOOK_TOOLS = ("search_runbooks", "get_runbook_section")


# --- loading ---------------------------------------------------------------------------------

def load_runs(run_dir: str) -> list:
    out = []
    for p in sorted(glob.glob(os.path.join(run_dir, "*.json"))):
        with open(p, encoding="utf-8") as fh:
            r = json.load(fh)
        if "steps" in r and "incident_id" in r:
            out.append(r)
    return out


def load_key(dataset: str = "datasets/v1") -> dict:
    with open(os.path.join(dataset, "incidents.jsonl"), encoding="utf-8") as fh:
        return {r["incident_id"]: r for r in map(json.loads, filter(str.strip, fh))}


def load_runbook_map(path: str = "datasets/eval/incident_runbooks.json") -> dict:
    with open(path, encoding="utf-8") as fh:
        return {k: v for k, v in json.load(fh).items() if not k.startswith("_")}


def calls_with_results(run: dict):
    """Yield (name, arguments, result_dict) for every tool call that has a recorded result."""
    for s in run["steps"]:
        args = {c["id"]: (c["name"], c["arguments"]) for c in s["tool_calls"]}
        for r in s["tool_results"]:
            name, a = args.get(r["call_id"], (r["name"], {}))
            yield name, a, r


# --- dynamic: per-tool usage, cost, reliability ------------------------------------------------

def per_tool(runs: list) -> dict:
    """name -> calls, runs using it, error rate and kinds, latency, rendered size.
    `chars_n` is how many calls carried a rendered_chars figure (0 on pre-week-2.5 runs)."""
    acc = defaultdict(lambda: {"calls": 0, "runs": set(), "errors": 0, "kinds": Counter(), "lat": [],
                               "chars": []})
    for i, run in enumerate(runs):
        for name, _, r in calls_with_results(run):
            a = acc[name]
            a["calls"] += 1
            a["runs"].add(i)
            a["errors"] += bool(r["is_error"])
            if r["is_error"]:
                a["kinds"][r.get("error_kind") or "unknown"] += 1
            a["lat"].append(r.get("latency_ms") or 0)
            if r.get("rendered_chars"):
                a["chars"].append(r["rendered_chars"])
    total_chars = sum(sum(a["chars"]) for a in acc.values()) or 1
    out = {}
    for name, a in sorted(acc.items()):
        out[name] = {
            "calls": a["calls"], "calls_per_run": a["calls"] / max(1, len(runs)),
            "runs_using": len(a["runs"]), "error_rate": a["errors"] / a["calls"],
            "error_kinds": dict(a["kinds"]), "mean_latency_ms": mean(a["lat"]),
            "chars_n": len(a["chars"]), "mean_chars": mean(a["chars"]) if a["chars"] else None,
            "chars_share": sum(a["chars"]) / total_chars if a["chars"] else None}
    return out


# --- dynamic: where does required evidence get lost? -------------------------------------------

def evidence_funnel(runs: list, key: dict) -> dict:
    """For every required evidence id, the furthest stage it reached:
         never_surfaced -> surfaced (a search/fetch returned it) -> fetched (get_events asked for it)
         -> cited (in the submitted verdict).
    The first gap is a SEARCH problem (the filters never hit it); surfaced-not-fetched is a
    SELECTION problem (it was on screen and ignored); fetched-not-cited is a REASONING problem.
    Runs without event_ids on their results can only be split at fetched/cited."""
    stages = Counter()
    usable = 0
    for run in runs:
        gt = key[run["incident_id"]]["ground_truth"]
        need = set(gt["required_evidence_event_ids"])
        surfaced, fetched, has_ids = set(), set(), False
        for name, args, r in calls_with_results(run):
            if "event_ids" in r:
                has_ids = True
                surfaced |= set(r["event_ids"])
            if name == "get_events" and not r["is_error"]:
                fetched |= set(args.get("event_ids") or [])
        cited = set((run.get("final_verdict") or {}).get("evidence_event_ids") or [])
        usable += has_ids
        for e in need:
            if e in cited:
                stages["cited"] += 1
            elif e in fetched:
                stages["fetched_not_cited"] += 1
            elif has_ids and e in surfaced:
                stages["surfaced_not_fetched"] += 1
            elif has_ids:
                stages["never_surfaced"] += 1
            else:
                stages["not_fetched (surfacing unknown)"] += 1
    total = sum(stages.values())
    return {"required_total": total, "runs_with_ids": usable, "n_runs": len(runs),
            "stages": {k: v for k, v in stages.items()},
            "fractions": {k: v / total for k, v in stages.items()} if total else {}}


# --- dynamic: runbook use ------------------------------------------------------------------------

def runbook_use(runs: list, key: dict, mapping: dict) -> dict:
    """Did the agent look at the right runbook, and did it read what it searched for?
    searched      the run called search_runbooks at all
    read          the run opened at least one section with get_runbook_section
    consulted     it opened a section of an expected runbook (read) -- needs no result ids
    surfaced      an expected runbook appeared in a search result (needs section_ids; n/a on old runs)
    A runbook is general guidance and never contains the answer, so `consulted` is a process metric:
    it says the agent followed the method, not that the verdict was right because of it."""
    n = len(runs)
    c = Counter()
    for run in runs:
        want = set(mapping.get(key[run["incident_id"]]["scenario"], []))
        searched = read = consulted = surfaced = has_ids = False
        for name, args, r in calls_with_results(run):
            if name == "search_runbooks":
                searched = True
                if "section_ids" in r:
                    has_ids = True
                    surfaced |= any(s.split("#")[0] in want for s in r["section_ids"])
            elif name == "get_runbook_section" and not r["is_error"]:
                read = True
                consulted |= str(args.get("section_id", "")).split("#")[0] in want
        c["searched"] += searched
        c["read"] += read
        c["consulted"] += consulted
        c["has_ids"] += has_ids
        c["surfaced"] += bool(surfaced)
        c["searched_no_read"] += searched and not read
    return {"n_runs": n, **dict(c)}


# --- outcome split by tool use (descriptive only) --------------------------------------------------

def outcome_by_use(runs: list, key: dict, tool: str) -> dict:
    """Verdict accuracy and required-evidence recall with vs without a tool being used in the run.
    Confounded by design: the agent chooses when to call a tool, and it calls more when the case is
    harder. Do not read the difference as the tool's effect."""
    groups = {True: [], False: []}
    for run in runs:
        used = any(n == tool for n, _, _ in calls_with_results(run))
        gt = key[run["incident_id"]]["ground_truth"]
        v = run.get("final_verdict") or {}
        need = set(gt["required_evidence_event_ids"])
        groups[used].append({"ok": float(v.get("verdict") == gt["verdict"]),
                             "recall": len(need & set(v.get("evidence_event_ids") or [])) / max(1, len(need))})
    return {("used" if u else "not_used"): {"n": len(g), "verdict": mean([x["ok"] for x in g]),
                                            "recall": mean([x["recall"] for x in g])}
            for u, g in groups.items() if g}


# --- static: schema lint -----------------------------------------------------------------------------

MIN_DESCRIPTION_CHARS = 60


def lint_schemas(schemas: list) -> dict:
    """Properties of the model-facing tool surface. `schemas` is the list the loop sends to the API:
    [{name, description, input_schema}]. Findings are for a human to weigh, not a pass/fail gate;
    only `undocumented_params` and a missing description are always worth fixing."""
    tools, findings = [], []
    for s in schemas:
        props = (s.get("input_schema") or {}).get("properties", {}) or {}
        undocumented = sorted(p for p, d in props.items() if not (d.get("description") or "").strip())
        blob = json.dumps({"name": s["name"], "description": s.get("description", ""),
                           "input_schema": s.get("input_schema", {})})
        row = {"name": s["name"], "description_chars": len(s.get("description") or ""),
               "n_params": len(props), "n_required": len((s.get("input_schema") or {}).get("required", [])),
               "undocumented_params": undocumented, "schema_chars": len(blob),
               "est_tokens": len(blob) // 4}
        tools.append(row)
        if row["description_chars"] < MIN_DESCRIPTION_CHARS:
            findings.append("%s: description is %d chars (< %d); say when to use it and what it returns"
                            % (s["name"], row["description_chars"], MIN_DESCRIPTION_CHARS))
        if undocumented:
            findings.append("%s: parameter(s) without a description: %s" % (s["name"], ", ".join(undocumented)))
    names = [t["name"] for t in tools]
    for dup in sorted({n for n in names if names.count(n) > 1}):
        findings.append("duplicate tool name: %s" % dup)
    return {"tools": tools, "total_est_tokens": sum(t["est_tokens"] for t in tools), "findings": findings}


def schemas_for(toolset: str) -> list:
    """Model-facing schemas for a toolset. Starts the toolset's MCP servers (about 12s for `full`)."""
    from warden.toolplane.client import McpRegistry
    with McpRegistry("WRD-0001", {}, toolset=toolset) as reg:
        return reg.schemas()


# --- reporting ----------------------------------------------------------------------------------------

def report(runs: list, key: dict, mapping: dict, lint: dict = None) -> str:
    out = ["%d runs" % len(runs), ""]
    out += ["| tool | calls/run | runs using | error rate | mean latency ms | mean chars (n) | share of chars |",
            "|---|---|---|---|---|---|---|"]
    for name, t in per_tool(runs).items():
        out.append("| %s | %.2f | %d/%d | %.1f%% | %.0f | %s | %s |" % (
            name, t["calls_per_run"], t["runs_using"], len(runs), 100 * t["error_rate"], t["mean_latency_ms"],
            "n/a" if t["mean_chars"] is None else "%.0f (%d)" % (t["mean_chars"], t["chars_n"]),
            "n/a" if t["chars_share"] is None else "%.0f%%" % (100 * t["chars_share"])))
    errs = {n: t["error_kinds"] for n, t in per_tool(runs).items() if t["error_kinds"]}
    if errs:
        out += ["", "error kinds: " + "; ".join("%s %s" % (n, k) for n, k in errs.items())]

    f = evidence_funnel(runs, key)
    out += ["", "required-evidence funnel (%d ids over %d runs; %d runs carry event_ids)"
            % (f["required_total"], f["n_runs"], f["runs_with_ids"])]
    for k, v in sorted(f["stages"].items(), key=lambda kv: -kv[1]):
        out.append("  %-34s %3d  %5.1f%%" % (k, v, 100 * f["fractions"][k]))

    if any(n in RUNBOOK_TOOLS for n in per_tool(runs)):
        u = runbook_use(runs, key, mapping)
        out += ["", "runbook use: searched %d/%d, read a section %d/%d, searched but never read %d, consulted the "
                "expected runbook %d/%d, expected runbook surfaced in search %s"
                % (u["searched"], u["n_runs"], u["read"], u["n_runs"], u["searched_no_read"], u["consulted"],
                   u["n_runs"], "%d/%d" % (u["surfaced"], u["has_ids"]) if u["has_ids"] else "n/a (no section_ids)")]
        out += ["  (descriptive only; confounded by what the agent chooses to call)"]
        for tool in ("search_runbooks",):
            for label, g in outcome_by_use(runs, key, tool).items():
                out.append("  %s %s: n=%d verdict %.0f%% recall %.0f%%" % (tool, label, g["n"],
                                                                            100 * g["verdict"], 100 * g["recall"]))
    if lint:
        out += ["", "static schema lint: %d tools, ~%d tokens of schema" % (len(lint["tools"]), lint["total_est_tokens"])]
        out += ["| tool | description chars | params (required) | undocumented | ~tokens |", "|---|---|---|---|---|"]
        for t in lint["tools"]:
            out.append("| %s | %d | %d (%d) | %s | %d |" % (t["name"], t["description_chars"], t["n_params"],
                                                         t["n_required"], ", ".join(t["undocumented_params"]) or "-",
                                                         t["est_tokens"]))
        out += ["  finding: " + x for x in lint["findings"]] or ["  no findings"]
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--dataset", default="datasets/v1")
    ap.add_argument("--runbook-map", default="datasets/eval/incident_runbooks.json")
    ap.add_argument("--lint", choices=("w1", "full"), help="also lint this toolset's schemas (starts MCP servers)")
    args = ap.parse_args()
    runs = load_runs(args.run_dir)
    if not runs:
        raise SystemExit("no run files in %s" % args.run_dir)
    lint = lint_schemas(schemas_for(args.lint)) if args.lint else None
    print(report(runs, load_key(args.dataset), load_runbook_map(args.runbook_map), lint))


if __name__ == "__main__":
    main()
