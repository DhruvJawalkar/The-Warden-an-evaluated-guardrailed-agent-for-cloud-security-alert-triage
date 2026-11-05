"""Worker process for the kill/resume test (tests/test_graph_resume.py). No API calls.

Runs one incident through the graph with a PostgresSaver and a scripted model that is deliberately
slow, so the test can kill the process mid-node. Every model call, tool call and verify entry is
appended to a ledger file, which survives the kill and is the independent record of what really ran.

    python scripts/graph_killtest_worker.py --thread T --ledger L [--model-delay 1.5] [--verify-delay 0]

Start-or-resume: if the thread has no checkpoint, start from the alert; if it has a pending next
node, continue from the checkpoint (invoke(None)); if it is finished, just print the report.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from langgraph.checkpoint.postgres import PostgresSaver

import warden.graph.build as build_mod
from warden.graph.build import build_graph, initial_state
from warden.graph.nodes import GraphDeps
from warden.loop.agent_loop import ModelResponse, ScriptedClient
from warden.loop.tools import IncidentStore, build_registry
from warden.loop.transcript import ToolCall, Usage

MODEL = "claude-haiku-4-5-20251001"
USAGE = Usage(1000, 200)  # fixed, so each model call costs the same and spend is countable
SEED = "evt-WRD-0001-0001"


def script() -> list:
    def call(i, tool, **args):
        return ModelResponse("", [ToolCall("t%d" % i, tool, args)], "tool_use", USAGE)
    return [call(1, "describe_principal", name="alice.chen"),
            call(2, "get_events", event_ids=[SEED]),
            call(3, "submit_verdict", verdict="true_positive", severity="high",
                 recommended_action="escalate", evidence_event_ids=[SEED],
                 rationale="Console login without MFA from a new ASN, then role assumption. " * 2)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--thread", required=True)
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--incident", default="WRD-0001")
    ap.add_argument("--dsn", default=os.environ.get(
        "WARDEN_PG_DSN", "postgresql://warden:warden@127.0.0.1:5433/warden"))
    ap.add_argument("--dataset", default=os.environ.get("WARDEN_DATASET", "datasets/v1"))
    ap.add_argument("--model-delay", type=float, default=0.0)
    ap.add_argument("--verify-delay", type=float, default=0.0)
    args = ap.parse_args()

    def log(ev: str) -> None:
        with open(args.ledger, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ev": ev, "pid": os.getpid(), "t": time.time()}) + "\n")

    class LoggedClient(ScriptedClient):
        def create(self, system, messages, tools):
            log("model")
            time.sleep(args.model_delay)
            return super().create(system, messages, tools)

    store = IncidentStore(args.dataset)

    def registry_factory(inc, run_state):
        reg = build_registry(store, inc, run_state)
        inner = reg.dispatch

        def dispatch(name, arguments):
            log("tool:" + name)
            return inner(name, arguments)
        reg.dispatch = dispatch
        return reg

    real_verify = build_mod.verify_node

    def slow_verify(deps):
        node = real_verify(deps)

        def verify_(state):
            log("verify_enter")
            time.sleep(args.verify_delay)
            return node(state)
        return verify_
    build_mod.verify_node = slow_verify

    deps = GraphDeps(store=store, client_factory=lambda: LoggedClient(script()), model=MODEL,
                     registry_factory=registry_factory)
    cfg = {"configurable": {"thread_id": args.thread}}
    with PostgresSaver.from_conn_string(args.dsn) as saver:
        saver.setup()
        graph = build_graph(deps, saver)
        snap = graph.get_state(cfg)
        if not snap.values:
            log("start")
            out = graph.invoke(initial_state(store, args.incident), cfg)
        elif snap.next:
            log("resume:" + ",".join(snap.next))
            out = graph.invoke(None, cfg)
        else:
            log("already_done")
            out = snap.values
    print(json.dumps({"report": out["report"], "observations": len(out["observations"]),
                      "cost_usd": out["cost_usd"], "verify_attempts": out["verify_attempts"]}))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
