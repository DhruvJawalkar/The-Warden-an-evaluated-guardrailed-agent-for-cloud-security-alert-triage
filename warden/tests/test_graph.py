"""Skeleton graph, offline: ScriptedClient + the in-process registry, MemorySaver checkpointer."""

from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("langgraph")

from langgraph.checkpoint.memory import MemorySaver  # noqa: E402

from warden.graph.build import build_graph, initial_state, thread_config  # noqa: E402
from warden.graph.nodes import GraphDeps  # noqa: E402
from warden.loop.agent_loop import ModelResponse, ScriptedClient  # noqa: E402
from warden.loop.tools import IncidentStore, build_registry  # noqa: E402
from warden.loop.transcript import ToolCall, Usage  # noqa: E402

ROOT = os.environ.get("WARDEN_DATASET", "datasets/v1")
INC = "WRD-0001"
SEED = "evt-WRD-0001-0001"
_n = [0]


def call(tool, **args):
    _n[0] += 1
    return ModelResponse("", [ToolCall("t%d" % _n[0], tool, args)], "tool_use", Usage(1, 1))


def submit(action="escalate", ids=(SEED,), verdict="true_positive"):
    return call("submit_verdict", verdict=verdict, severity="high", recommended_action=action,
                evidence_event_ids=list(ids), rationale="Console login without MFA from a new ASN. " * 2)


def passing_attempt():
    """describe the alerting principal, fetch the seed, pivot on its resource if any, submit."""
    return [call("describe_principal", name="alice.chen"), call("get_events", event_ids=[SEED]),
            submit()]


def make(script, **kw):
    store = IncidentStore(ROOT)
    client = ScriptedClient(script)
    deps = GraphDeps(store=store, client_factory=lambda: client, model="scripted",
                     registry_factory=lambda inc, rs: build_registry(store, inc, rs), **kw)
    saver = MemorySaver()
    return build_graph(deps, saver), deps, client, saver


def run(graph, deps):
    return graph.invoke(initial_state(deps.store, INC), thread_config(INC))


def test_clean_run_is_verified_without_retry():
    graph, deps, client, _ = make(passing_attempt())
    out = run(graph, deps)
    rep = out["report"]
    assert rep["status"] == "verified" and out["verify_attempts"] == 1
    assert out["gaps"] == [] and out["plan"]
    assert [o["tool"] for o in out["observations"]] == ["describe_principal", "get_events",
                                                        "submit_verdict"]


def test_failed_check_routes_back_once_and_then_passes():
    first = [call("get_events", event_ids=[SEED]), submit()]  # never described anyone
    graph, deps, client, _ = make(first + passing_attempt())
    out = run(graph, deps)
    assert out["report"]["status"] == "verified" and out["verify_attempts"] == 2
    # append-only: the retry added observations, the first attempt's are still there
    assert len(out["observations"]) == 2 + 3


def test_retry_ceiling_is_one():
    bad = lambda: [call("get_events", event_ids=[SEED]), submit()]  # noqa: E731
    graph, deps, client, _ = make(bad() + bad() + bad())
    out = run(graph, deps)
    assert out["verify_attempts"] == 2  # one retry, not two
    assert out["report"]["status"] == "unverified"
    assert out["report"]["gaps"]
    assert len(client.script) == 2, "the third attempt must never have been consumed"


def test_no_verdict_is_unresolved_and_proposes_no_ticket():
    graph, deps, _, _ = make([])
    out = run(graph, deps)
    assert out["report"]["status"] == "unresolved" and out["ticket"] is None
    assert out["verify_attempts"] == 1  # nothing to retry


def test_escalation_is_a_proposal_not_a_write():
    graph, deps, _, _ = make(passing_attempt())
    out = run(graph, deps)
    assert out["ticket"]["recommended_action"] == "escalate"
    assert out["ticket"]["evidence_event_ids"] == [SEED]
    tools = {o["tool"] for o in out["observations"]}
    assert "create_ticket" not in tools


def test_close_benign_proposes_no_ticket():
    script = [call("describe_principal", name="alice.chen"), call("get_events", event_ids=[SEED]),
              submit(action="close_benign", verdict="false_positive")]
    graph, deps, _, _ = make(script)
    assert run(graph, deps)["ticket"] is None


def test_state_is_checkpointed_and_serialisable():
    graph, deps, _, saver = make(passing_attempt())
    run(graph, deps)
    snap = graph.get_state(thread_config(INC))
    assert snap.next == () and snap.values["report"]["status"] == "verified"
    json.dumps(snap.values, default=str)  # nothing live leaked into state
    history = list(graph.get_state_history(thread_config(INC)))
    assert len(history) >= 5  # input, plan, investigate, verify, report


def test_spend_cap_stops_a_retry():
    graph, deps, client, _ = make([call("get_events", event_ids=[SEED]), submit()] +
                                  passing_attempt(), max_usd=0.0)
    out = run(graph, deps)
    assert out["stop_cause"] == "max_usd" and out["report"]["status"] == "unresolved"
