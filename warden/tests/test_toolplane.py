"""The FastMCP tool plane must be indistinguishable from the in-process one to the loop.

The in-process registry (`build_registry`) is the oracle. Nothing here calls a model: parity is
asserted deterministically over every incident, which is stronger evidence that the port did not
regress than a single n=1 eval run.
"""

from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("fastmcp")

from warden.loop.tools import IncidentStore, ToolError, build_registry  # noqa: E402
from warden.toolplane.client import McpRegistry  # noqa: E402

ROOT = os.environ.get("WARDEN_DATASET", "datasets/v1")


@pytest.fixture(scope="module")
def store():
    return IncidentStore(ROOT)


@pytest.fixture(scope="module")
def mcp_reg(store):
    reg = McpRegistry(store.incident_ids()[0], {}, dataset=ROOT).start()
    yield reg
    reg.close()


def bind(reg: McpRegistry, incident_id: str, state: dict) -> McpRegistry:
    """Re-point the shared registry at another incident (tests only; a run binds once)."""
    reg.incident_id = incident_id
    reg.fetched.clear()
    reg._local = type(reg._local)()
    from warden.loop.tools import make_submit_verdict_tool
    reg._local.add(make_submit_verdict_tool(state, reg.fetched))
    return reg


def roundtrip(payload):
    return json.loads(json.dumps(payload, default=str))


# --- what the model sees -------------------------------------------------------

def test_model_facing_schemas_identical(store, mcp_reg):
    inproc = build_registry(store, store.incident_ids()[0], {})
    assert mcp_reg.names() == inproc.names()
    assert mcp_reg.schemas() == inproc.schemas(), "the port changed what the model is shown"


def test_incident_id_is_hidden_from_model(mcp_reg):
    for s in mcp_reg.schemas():
        assert "incident_id" not in json.dumps(s["input_schema"])


# --- payload parity, every incident --------------------------------------------

def test_payload_parity_all_incidents(store, mcp_reg):
    for iid in store.incident_ids():
        state_a, state_b = {}, {}
        ref = build_registry(store, iid, state_a)
        got = bind(mcp_reg, iid, state_b)
        events = store.events(iid)
        principals = sorted({e["principal_name"] for e in events})
        calls = [
            ("search_logs", {"limit": 100}),
            ("search_logs", {"errors_only": True}),
            ("search_logs", {"writes_only": True, "limit": 5}),
            ("search_logs", {"principal_name": principals[0]}),
            ("search_logs", {"contains": "s3", "limit": 3}),
            ("search_logs", {"time_from": events[0]["event_time"], "time_to": events[-1]["event_time"]}),
            ("get_events", {"event_ids": [e["event_id"] for e in events[:5]]}),
        ] + [("describe_principal", {"name": p}) for p in principals if p in store.principals]
        for name, args in calls:
            want, _ = ref.dispatch(name, dict(args))
            have, _ = got.dispatch(name, dict(args))
            assert roundtrip(want) == have, "%s %s %s diverged" % (iid, name, args)


# --- errors keep their kind across the wire -------------------------------------

def _kind(reg, name, args):
    with pytest.raises(ToolError) as e:
        reg.dispatch(name, args)
    return e.value.kind


def test_tool_errors_are_typed_over_the_wire(store, mcp_reg):
    reg = bind(mcp_reg, "WRD-0001", {})
    assert _kind(reg, "no_such_tool", {}) == "unknown_tool"
    assert _kind(reg, "search_logs", {"nonsense_filter": "x"}) == "bad_arguments"
    assert _kind(reg, "get_events", {"event_ids": ["evt-nope"]}) == "bad_arguments"
    assert _kind(reg, "get_events", {}) == "bad_arguments"  # missing required, server-side validation
    assert _kind(reg, "search_logs", {"limit": "many"}) == "bad_arguments"  # wrong type
    assert _kind(reg, "describe_principal", {"name": "nobody"}) == "bad_arguments"


def test_validation_message_is_clean(mcp_reg):
    reg = bind(mcp_reg, "WRD-0001", {})
    with pytest.raises(ToolError) as e:
        reg.dispatch("search_logs", {"limit": "many"})
    msg = str(e.value)
    assert "limit" in msg and "pydantic" not in msg and "For further information" not in msg


def test_model_cannot_choose_the_incident(mcp_reg):
    """A log line steering the model to read another incident must not work."""
    reg = bind(mcp_reg, "WRD-0001", {})
    assert _kind(reg, "search_logs", {"incident_id": "WRD-0002"}) == "bad_arguments"
    payload, _ = reg.dispatch("search_logs", {"limit": 1})
    assert all("WRD-0001" in e["event_id"] for e in payload["events"])


# --- submit_verdict stays client-side and keeps its evidence rule ---------------

def test_submit_verdict_requires_fetched_evidence_over_mcp(mcp_reg):
    state: dict = {}
    reg = bind(mcp_reg, "WRD-0001", state)
    args = {"verdict": "true_positive", "severity": "high", "recommended_action": "escalate",
            "evidence_event_ids": ["evt-WRD-0001-0001"], "rationale": "x" * 50}
    with pytest.raises(ToolError) as e:
        reg.dispatch("submit_verdict", dict(args))
    assert e.value.kind == "bad_arguments" and "evt-WRD-0001-0001" in str(e.value)
    assert state == {}
    reg.dispatch("get_events", {"event_ids": ["evt-WRD-0001-0001"]})
    reg.dispatch("submit_verdict", dict(args))
    assert state["verdict"]["evidence_event_ids"] == ["evt-WRD-0001-0001"]


def test_agent_loop_runs_unchanged_over_mcp(mcp_reg):
    """The loop is untouched: a scripted model drives search -> fetch -> verdict over stdio."""
    from warden.loop.agent_loop import AgentLoop, Budget, ModelResponse, ScriptedClient
    from warden.loop.transcript import RunRecord, ToolCall, Transcript, Usage

    state: dict = {}
    reg = bind(mcp_reg, "WRD-0001", state)
    eid = "evt-WRD-0001-0001"
    script = [
        ModelResponse("", [ToolCall("a", "search_logs", {"limit": 3})], "tool_use", Usage(10, 10)),
        ModelResponse("", [ToolCall("b", "get_events", {"event_ids": [eid]})], "tool_use", Usage(10, 10)),
        ModelResponse("", [ToolCall("c", "submit_verdict", {
            "verdict": "true_positive", "severity": "high", "recommended_action": "escalate",
            "evidence_event_ids": [eid], "rationale": "x" * 50})], "tool_use", Usage(10, 10)),
    ]
    tr = Transcript("system")
    tr.add_user("go")
    run = RunRecord.new("WRD-0001", "scripted")
    out = AgentLoop(ScriptedClient(script), reg, tr, Budget(), run, state).run_until_done()
    assert out.stop_cause == "verdict_submitted"
    assert out.tool_call_names() == ["search_logs", "get_events", "submit_verdict"]
    assert out.final_verdict["evidence_event_ids"] == [eid]
    assert not any(r.is_error for s in out.steps for r in s.tool_results)


def test_failed_get_events_does_not_unlock_evidence(mcp_reg):
    state: dict = {}
    reg = bind(mcp_reg, "WRD-0001", state)
    with pytest.raises(ToolError):
        reg.dispatch("get_events", {"event_ids": ["evt-WRD-0001-0001", "evt-nope"]})
    assert "evt-WRD-0001-0001" not in reg.fetched
