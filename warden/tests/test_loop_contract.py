"""Contract tests for the hand-written loop.

The first two pass today. The rest are the tests your week-1 implementations
must satisfy — they skip until the corresponding stub is implemented, so
`pytest -q` is a live progress bar for the week.

Write the implementation against these, not the other way round.
"""

from __future__ import annotations

import os

import pytest

from warden.loop.agent_loop import AgentLoop, Budget, ModelResponse, ScriptedClient, NotImplementedStub
from warden.loop.tools import IncidentStore, ToolError, build_registry
from warden.loop.transcript import RunRecord, ToolCall, Transcript, Usage

ROOT = os.environ.get("WARDEN_DATASET", "datasets/v1")


def make_loop(script=None, max_steps=25):
    store = IncidentStore(ROOT)
    state: dict = {}
    reg = build_registry(store, "WRD-0001", state)
    tr = Transcript("system")
    tr.add_user("go")
    run = RunRecord.new("WRD-0001", "scripted")
    return AgentLoop(ScriptedClient(script or []), reg, tr, Budget(max_steps=max_steps),
                     run, state), state


def skip_if_stub(loop, name, *args):
    try:
        getattr(loop, name)(*args)
    except NotImplementedStub:
        pytest.skip("%s not implemented yet" % name)
    except Exception:
        pass


# --- passing today -----------------------------------------------------------

def test_tool_errors_are_typed_not_crashes():
    store = IncidentStore(ROOT)
    reg = build_registry(store, "WRD-0001", {})
    with pytest.raises(ToolError) as e1:
        reg.dispatch("no_such_tool", {})
    assert e1.value.kind == "unknown_tool"
    with pytest.raises(ToolError) as e2:
        reg.dispatch("search_logs", {"nonsense_filter": "x"})
    assert e2.value.kind == "bad_arguments"
    with pytest.raises(ToolError) as e3:
        reg.dispatch("get_events", {"event_ids": ["evt-nope"]})
    assert e3.value.kind == "bad_arguments"


def test_submit_verdict_rejects_invalid_payloads():
    store = IncidentStore(ROOT)
    state: dict = {}
    reg = build_registry(store, "WRD-0001", state)
    with pytest.raises(ToolError):
        reg.dispatch("submit_verdict", {"verdict": "maybe", "severity": "high",
                                        "recommended_action": "escalate",
                                        "evidence_event_ids": ["evt-1"], "rationale": "x" * 50})
    assert state == {}


# --- your week-1 targets -----------------------------------------------------

def test_render_truncates_and_says_so():
    """A truncated result must tell the model it was truncated."""
    loop, _ = make_loop()
    payload, _ = loop.registry.dispatch("search_logs", {"limit": 100})
    skip_if_stub(loop, "render_tool_result",
                 __import__("warden.loop.transcript", fromlist=["ToolResult"]).ToolResult(
                     call_id="t", name="search_logs", payload=payload))
    from warden.loop.transcript import ToolResult
    text = loop.render_tool_result(ToolResult(call_id="t", name="search_logs", payload=payload))
    assert isinstance(text, str) and text
    assert len(text) < 12000, "render is too generous with the context window"
    assert str(payload["total_matched"]) in text, "model cannot tell how much it did not see"


def test_stops_once_verdict_submitted():
    loop, state = make_loop()
    skip_if_stub(loop, "should_stop", loop.run)
    assert loop.should_stop(loop.run) is None
    state["verdict"] = {"verdict": "true_positive"}
    assert loop.should_stop(loop.run), "must stop once a verdict exists"


def test_compaction_preserves_tool_use_result_pairing():
    """The invariant that breaks provider calls. Make this one pass first."""
    loop, _ = make_loop()
    for i in range(12):
        loop.transcript.add_assistant_blocks(
            [{"type": "tool_use", "id": "t%d" % i, "name": "search_logs", "input": {}}])
        loop.transcript.add_tool_results([("t%d" % i, "x" * 3000, False)])
    skip_if_stub(loop, "maybe_compact")
    loop.budget.max_context_tokens = 2000
    loop.maybe_compact()
    uses, results = set(), set()
    for msg in loop.transcript.messages:
        for block in msg["content"]:
            if block.get("type") == "tool_use":
                uses.add(block["id"])
            elif block.get("type") == "tool_result":
                results.add(block["tool_use_id"])
    assert uses == results, "orphaned tool_use/tool_result after compaction: %s" % (uses ^ results)


def test_loop_terminates_on_step_ceiling():
    """A model that never submits a verdict must not run forever."""
    forever = [ModelResponse("thinking", [ToolCall("t%d" % i, "search_logs", {"limit": 1})],
                             "tool_use", Usage(10, 10)) for i in range(50)]
    loop, _ = make_loop(script=forever, max_steps=5)
    skip_if_stub(loop, "should_stop", loop.run)
    try:
        run = loop.run_until_done()
    except NotImplementedStub as exc:
        pytest.skip("still stubbed: %s" % exc)
    assert len(run.steps) <= 5
    assert run.stop_cause in ("max_steps", "stalled_no_progress"), run.stop_cause


def test_submit_verdict_requires_fetched_evidence():
    store = IncidentStore(ROOT)
    state: dict = {}
    reg = build_registry(store, "WRD-0001", state)
    args = {"verdict": "true_positive", "severity": "high", "recommended_action": "escalate",
            "evidence_event_ids": ["evt-WRD-0001-0001"], "rationale": "x" * 50}
    with pytest.raises(ToolError) as e:
        reg.dispatch("submit_verdict", args)  # seen in an alert, never fetched
    assert e.value.kind == "bad_arguments" and "evt-WRD-0001-0001" in str(e.value)
    assert state == {}
    reg.dispatch("get_events", {"event_ids": ["evt-WRD-0001-0001"]})
    reg.dispatch("submit_verdict", args)
    assert state["verdict"]["evidence_event_ids"] == ["evt-WRD-0001-0001"]
