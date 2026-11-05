"""Batch runner: many incidents through the graph, with a recorded gate policy.

    python -m warden.graph.batch run --experiment w3-graph --hold-first 1     # real model, costs money
    python -m warden.graph.batch pending --experiment w3-graph                # what is waiting on a human
    python -m warden.graph.batch decide --experiment w3-graph --incident WRD-0003 --action approve --reviewer dhruv
    python -m warden.graph.batch purge [--experiment E] [--ttl-hours 6]

Gate policy. Every contain/escalate verdict and every unresolved run stops at the gate. In a batch:
  * held threads stay paused for a human (`--hold ID,ID` and/or `--hold-first N`: the first N incidents
    to reach the gate with a proposed ticket). They are the manual-approval cases.
  * every other gate is auto-rejected, recorded as reviewer "eval-harness": no ticket is filed and
    the gate's wait time is not in the run's latency.
A thread that is already paused when a run starts is left paused, never auto-rejected, unless
`--auto-reject-pending` says so. A thread that already finished is not re-run (spend protection).
Thread ids are `<experiment>:<incident>`; stale threads (default 6 h) are purged at the start of a run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Optional

from langgraph.types import Command

from warden.graph.build import build_graph, initial_state, thread_config
from warden.graph.nodes import GraphDeps
from warden.graph.threads import DEFAULT_TTL_HOURS, purge_stale, split_thread_id

REVIEWER = "eval-harness"
AUTO_REJECT = {"action": "reject", "reviewer": REVIEWER,
               "reason": "batch policy: auto-reject, no human in the loop"}
DEFAULT_DSN = "postgresql://warden:warden@127.0.0.1:5433/warden"


def _gate_payload(graph, cfg) -> Optional[dict]:
    snap = graph.get_state(cfg)
    if snap.next != ("gate",):
        return None
    for task in snap.tasks:
        for itr in getattr(task, "interrupts", ()):
            return itr.value
    return {}


def _row(graph, cfg, experiment, incident, how, seconds, held=False) -> dict:
    snap = graph.get_state(cfg)
    v = snap.values
    d = v.get("human_decision") or {}
    return {
        "incident_id": incident, "thread_id": cfg["configurable"]["thread_id"], "started": how,
        "status": (v.get("report") or {}).get("status"), "disposition": v.get("disposition"),
        "paused_at_gate": snap.next == ("gate",), "held_for_human": held,
        "decision": d.get("action"), "reviewer": d.get("reviewer"),
        "verdict": (v.get("verdict") or {}).get("verdict"),
        "cost_usd": round(v.get("cost_usd", 0.0), 6), "stop_cause": v.get("stop_cause"),
        "verify_attempts": v.get("verify_attempts"), "seconds_excl_gate_wait": round(seconds, 2),
    }


def run_experiment(graph, deps: GraphDeps, experiment: str, incidents: list, hold_ids=(),
                   hold_first: int = 0, auto_reject_pending: bool = False, log=print) -> list:
    rows, held_count = [], 0
    for inc in incidents:
        cfg = thread_config(inc, experiment)
        snap = graph.get_state(cfg)
        t0 = time.time()
        if snap.values and not snap.next:
            rows.append(_row(graph, cfg, experiment, inc, "already_done", 0.0))
            log("%s: already finished, not re-run" % inc)
            continue
        if not snap.values:
            how = "fresh"
            graph.invoke(initial_state(deps.store, inc), cfg)
        elif snap.next == ("gate",):
            how = "found_paused"
        else:
            how = "resumed"
            graph.invoke(None, cfg)
        elapsed = time.time() - t0  # up to the gate; whatever happens at the gate is policy, not latency

        payload = _gate_payload(graph, cfg)
        held = False
        if payload is not None:
            if how == "found_paused":
                held = not auto_reject_pending
            else:
                by_count = payload.get("kind") == "proposed_ticket" and held_count < hold_first
                held_count += int(by_count and inc not in hold_ids)
                held = inc in hold_ids or by_count
            if not held:
                graph.invoke(Command(resume=dict(AUTO_REJECT)), cfg)
        rows.append(_row(graph, cfg, experiment, inc, how, elapsed, held))
        r = rows[-1]
        log("%s: %s/%s cost $%.4f%s" % (inc, r["status"], r["disposition"], r["cost_usd"],
                                         "  ** HELD for a human decision **" if held else ""))
    return rows


def pending_gates(graph, experiment: str, incidents: list) -> list:
    out = []
    for inc in incidents:
        payload = _gate_payload(graph, thread_config(inc, experiment))
        if payload is not None:
            out.append({"incident_id": inc, **payload})
    return out


def apply_decision(graph, experiment: str, incident: str, decision: dict) -> dict:
    """Resume one paused thread with a human decision. Refuses if the thread is not at the gate."""
    cfg = thread_config(incident, experiment)
    if _gate_payload(graph, cfg) is None:
        raise ValueError("%s:%s is not paused at the gate" % (experiment, incident))
    graph.invoke(Command(resume=decision), cfg)
    return _row(graph, cfg, experiment, incident, "decided", 0.0)


# --- CLI -------------------------------------------------------------------------

def _build(args):
    from langgraph.checkpoint.postgres import PostgresSaver  # noqa: F401  (import check)
    from warden.loop.agent_loop import AnthropicClient
    from warden.loop.tools import IncidentStore
    from warden.toolplane.client import open_registry
    store = IncidentStore(args.dataset)
    deps = GraphDeps(
        store=store, client_factory=lambda: AnthropicClient(args.model), model=args.model,
        prompt_version=args.prompt, compaction=args.compaction, max_steps=args.max_steps, max_usd=args.max_usd,
        registry_factory=lambda inc, rs: open_registry("mcp", store, inc, rs, dataset=args.dataset,
                                                       toolset="w1"),
        run_dir=os.path.join(args.run_dir, args.experiment))
    return store, deps


def main(argv=None) -> int:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:  # pragma: no cover
        pass
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=("run", "pending", "decide", "purge"))
    ap.add_argument("--experiment")
    ap.add_argument("--incidents", help="comma list; default all")
    ap.add_argument("--dsn", default=os.environ.get("WARDEN_PG_DSN", DEFAULT_DSN))
    ap.add_argument("--dataset", default=os.environ.get("WARDEN_DATASET", "datasets/v1"))
    ap.add_argument("--model", default=os.environ.get("WARDEN_MODEL", "claude-haiku-4-5-20251001"))
    ap.add_argument("--prompt", default="v2")
    ap.add_argument("--compaction", choices=("elide", "summarise"), default="elide")
    ap.add_argument("--max-steps", type=int, default=25)
    ap.add_argument("--max-usd", type=float, default=0.50)
    ap.add_argument("--run-dir", default="runs")
    ap.add_argument("--hold", default="", help="comma list of incident ids to leave at the gate")
    ap.add_argument("--hold-first", type=int, default=1,
                    help="also hold the first N incidents that reach the gate with a proposed ticket")
    ap.add_argument("--auto-reject-pending", action="store_true")
    ap.add_argument("--ttl-hours", type=float, default=DEFAULT_TTL_HOURS)
    ap.add_argument("--incident")
    ap.add_argument("--action", choices=("approve", "reject", "edit"))
    ap.add_argument("--edits", help="JSON object of edits, for --action edit")
    ap.add_argument("--reason", default="")
    ap.add_argument("--reviewer", default="")
    args = ap.parse_args(argv)

    import psycopg
    from langgraph.checkpoint.postgres import PostgresSaver
    if args.cmd != "purge" and not args.experiment:
        ap.error("--experiment is required")
    with PostgresSaver.from_conn_string(args.dsn) as saver, psycopg.connect(args.dsn) as conn:
        saver.setup()
        if args.cmd == "purge":
            gone = purge_stale(saver, conn, args.ttl_hours, experiment=args.experiment)
            print(json.dumps({"purged": gone, "ttl_hours": args.ttl_hours}))
            return 0
        from warden.loop.tools import IncidentStore
        ids = [i for i in (args.incidents or "").split(",") if i] or IncidentStore(args.dataset).incident_ids()
        if args.cmd == "run":
            gone = purge_stale(saver, conn, args.ttl_hours)
            if gone:
                print("purged %d stale thread(s): %s" % (len(gone), ", ".join(gone)), file=sys.stderr)
            store, deps = _build(args)
            graph = build_graph(deps, saver)
            rows = run_experiment(graph, deps, args.experiment, ids,
                                  hold_ids={i for i in args.hold.split(",") if i},
                                  hold_first=args.hold_first,
                                  auto_reject_pending=args.auto_reject_pending, log=lambda m: print(m, file=sys.stderr))
            out = os.path.join(args.run_dir, args.experiment)
            os.makedirs(out, exist_ok=True)
            with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as fh:
                json.dump({"experiment": args.experiment, "model": args.model, "prompt": args.prompt,
                           "ttl_hours": args.ttl_hours, "rows": rows}, fh, indent=2)
            print(json.dumps({"rows": len(rows), "total_cost_usd": round(sum(r["cost_usd"] for r in rows), 4),
                              "held": [r["incident_id"] for r in rows if r["held_for_human"]]}))
            return 0
        # pending / decide need the graph but never call the model
        from warden.loop.tools import IncidentStore as _S
        deps = GraphDeps(store=_S(args.dataset), client_factory=None, model=args.model, registry_factory=None)
        graph = build_graph(deps, saver)
        if args.cmd == "pending":
            print(json.dumps(pending_gates(graph, args.experiment, ids), indent=2))
            return 0
        if not args.incident or not args.action:
            ap.error("decide needs --incident and --action")
        decision = {"action": args.action, "reviewer": args.reviewer or "unknown"}
        if args.action == "reject":
            decision["reason"] = args.reason or "rejected"
        if args.action == "edit":
            decision["edits"] = json.loads(args.edits or "{}")
        print(json.dumps(apply_decision(graph, args.experiment, args.incident, decision), indent=2))
        return 0


if __name__ == "__main__":
    sys.exit(main())
