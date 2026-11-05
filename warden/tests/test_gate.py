"""Interrupt gate: decision parsing (pure), then approve / reject / edit through the real graph."""

from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("langgraph")

from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.types import Command  # noqa: E402

from warden.graph.build import build_graph, initial_state, thread_config  # noqa: E402
from warden.graph.gate import decide, proposal_for  # noqa: E402
from warden.graph.nodes import GraphDeps, file_ticket_node, route_after_gate  # noqa: E402
from warden.loop.agent_loop import ScriptedClient  # noqa: E402
from warden.loop.tools import IncidentStore, ToolError, build_registry  # noqa: E402

from .test_graph import INC, SEED, call, passing_attempt, submit  # noqa: E402

ROOT = os.environ.get("WARDEN_DATASET", "datasets/v1")
PROPOSED = {"title": "T", "severity": "high", "recommended_action": "escalate", "body": "why",
            "evidence_event_ids": [SEED]}


# --- decide(): fail closed -----------------------------------------------------------

def test_approve_files_exactly_the_proposal():
    d = decide({"action": "approve", "reviewer": "ana"}, PROPOSED)
    assert d["action"] == "approve" and d["ticket"] == PROPOSED and d["reviewer"] == "ana"
    assert d["ticket"] is not PROPOSED  # a copy


def test_edit_changes_only_named_fields_and_keeps_evidence():
    d = decide({"action": "edit", "edits": {"severity": "critical", "body": "new"}}, PROPOSED)
    assert d["action"] == "edit"
    assert d["ticket"] == {**PROPOSED, "severity": "critical", "body": "new"}
    assert PROPOSED["severity"] == "high"  # the proposal itself is untouched


def test_reject_carries_its_reason():
    d = decide({"action": "reject", "reason": "known pentest"}, PROPOSED)
    assert d == {"action": "reject", "ticket": None, "reason": "known pentest", "reviewer": ""}


@pytest.mark.parametrize("raw", [
    None, "approve", True, 1, [], {}, {"action": None}, {"action": "APPROVE"}, {"action": "yes"},
    {"action": "approve", "ticket": {"title": "x"}},            # approve cannot smuggle a ticket
    {"action": "approve", "edits": {"body": "x"}},
    {"action": "edit"}, {"action": "edit", "edits": {}}, {"action": "edit", "edits": "body"},
    {"action": "edit", "edits": {"evidence_event_ids": ["evt-x"]}},   # evidence is not editable
    {"action": "edit", "edits": {"incident_id": "WRD-0002"}},
    {"action": "edit", "edits": {"severity": "catastrophic"}},
    {"action": "edit", "edits": {"recommended_action": "delete_account"}},
    {"action": "edit", "edits": {"title": ""}}, {"action": "edit", "edits": {"title": "x" * 201}},
    {"action": "edit", "edits": {"body": "   "}},
    {"action": "edit", "edits": {"body": "ok", "bogus": 1}},          # one bad field rejects all
    {"action": "edit", "edits": {"body": "ok"}, "extra": 1},
])
def test_anything_malformed_is_a_reject(raw):
    d = decide(raw, PROPOSED)
    assert d["action"] == "reject" and d["ticket"] is None and d["reason"]


def test_proposals():
    alert = {"rule_name": "R", "primary_principal": "p", "severity_reported": "high",
             "seed_event_ids": ["e0"]}
    v = {"verdict": "true_positive", "severity": "critical", "recommended_action": "contain",
         "evidence_event_ids": ["e1"], "rationale": "r"}
    assert proposal_for({"alert": alert, "verdict": v})["evidence_event_ids"] == ["e1"]
    assert proposal_for({"alert": alert, "verdict": {**v, "recommended_action": "close_benign"}}) is None
    assert proposal_for({"alert": alert, "verdict": {**v, "recommended_action": "monitor"}}) is None
    un = proposal_for({"alert": alert, "verdict": None, "stop_cause": "max_steps"})
    assert un["recommended_action"] == "escalate" and un["evidence_event_ids"] == ["e0"]
    assert "max_steps" in un["body"]
    assert proposal_for({"alert": {**alert, "seed_event_ids": []}, "verdict": None}) is None
    odd = proposal_for({"alert": {**alert, "severity_reported": "weird"}, "verdict": None})
    assert odd["severity"] == "medium"


# --- through the graph ---------------------------------------------------------------

class FakeTicketRegistry:
    """Enforces the approver exactly like McpRegistry does, and records what would be written."""

    def __init__(self, approver, writes):
        self.approver, self.writes = approver, writes

    def dispatch(self, name, arguments):
        if not self.approver(name, dict(arguments)):
            raise ToolError("approval required", kind="approval_required")
        self.writes.append(dict(arguments))
        return {"ticket_id": "TKT-fake", "status": "open"}, 1


def bare_deps(factory):
    return GraphDeps(store=IncidentStore(ROOT), client_factory=None, model="x", registry_factory=None,
                     ticket_registry_factory=factory)


def make(script, writes, **kw):
    store = IncidentStore(ROOT)
    deps = GraphDeps(store=store, client_factory=lambda: ScriptedClient(script), model="scripted",
                     registry_factory=lambda inc, rs: build_registry(store, inc, rs),
                     ticket_registry_factory=lambda inc, approver: FakeTicketRegistry(approver, writes),
                     **kw)
    return build_graph(deps, MemorySaver()), deps


def to_gate(script, writes, **kw):
    graph, deps = make(script, writes, **kw)
    out = graph.invoke(initial_state(deps.store, INC), thread_config(INC))
    assert graph.get_state(thread_config(INC)).next == ("gate",), "graph did not pause"
    return graph, out


def resume(graph, value):
    return graph.invoke(Command(resume=value), thread_config(INC))


def test_nothing_is_written_while_the_gate_is_pending():
    writes = []
    graph, out = to_gate(passing_attempt(), writes)
    payload = out["__interrupt__"][0].value
    assert payload["kind"] == "proposed_ticket" and payload["ticket"]["evidence_event_ids"] == [SEED]
    assert payload["allowed"]["actions"] == ["approve", "edit", "reject"]
    assert writes == [] and out.get("filed_ticket") is None


def test_approve_writes_once_with_the_proposed_ticket():
    writes = []
    graph, out = to_gate(passing_attempt(), writes)
    proposed = out["ticket"]
    final = resume(graph, {"action": "approve", "reviewer": "ana"})
    assert writes == [proposed] and final["disposition"] == "filed"
    assert final["filed_ticket"]["ticket_id"] == "TKT-fake"
    assert final["human_decision"]["reviewer"] == "ana"
    assert graph.get_state(thread_config(INC)).next == ()


def test_edit_writes_the_edited_ticket():
    writes = []
    graph, out = to_gate(passing_attempt(), writes)
    final = resume(graph, {"action": "edit", "edits": {"severity": "low", "title": "Edited"}})
    assert len(writes) == 1 and writes[0]["severity"] == "low" and writes[0]["title"] == "Edited"
    assert writes[0]["evidence_event_ids"] == [SEED] and final["disposition"] == "filed"
    assert final["human_decision"]["action"] == "edit"


def test_reject_writes_nothing():
    writes = []
    graph, _ = to_gate(passing_attempt(), writes)
    final = resume(graph, {"action": "reject", "reason": "pentest"})
    assert writes == [] and final["disposition"] == "rejected" and final.get("filed_ticket") is None
    assert final["human_decision"]["reason"] == "pentest"


@pytest.mark.parametrize("junk", ["approve", {"action": "maybe"}, {"action": "approve", "ticket": {}},
                                  {"action": "edit", "edits": {"evidence_event_ids": ["x"]}}])
def test_garbage_resume_fails_closed(junk):
    writes = []
    graph, _ = to_gate(passing_attempt(), writes)
    final = resume(graph, junk)
    assert writes == [] and final["disposition"] == "rejected"
    assert final["human_decision"]["reason"].startswith(("invalid_resume", "rejected"))


@pytest.mark.parametrize("nothing", [None, {}])
def test_no_reply_at_all_leaves_the_gate_pending_and_writes_nothing(nothing):
    """LangGraph treats resume={} as "no reply" (re-pauses) and raises on resume=None (observed on
    langgraph 1.2.17). Either way: nothing is written, the gate is still open, and a later valid
    reply still works. Pinned so a langgraph upgrade that changes this is noticed."""
    writes = []
    graph, _ = to_gate(passing_attempt(), writes)
    try:
        resume(graph, nothing)
    except Exception:  # noqa: BLE001
        pass
    assert writes == [] and graph.get_state(thread_config(INC)).next == ("gate",)
    assert resume(graph, {"action": "approve"})["disposition"] == "filed" and len(writes) == 1


def test_unresolved_budget_exhaustion_becomes_a_human_decision():
    writes = []
    graph, out = to_gate([call("get_events", event_ids=[SEED])], writes, max_steps=1)
    assert out["report"]["status"] == "unresolved" and out["stop_cause"] == "max_steps"
    payload = out["__interrupt__"][0].value
    assert payload["kind"] == "unresolved" and payload["ticket"]["title"].startswith("UNRESOLVED")
    assert writes == []
    final = resume(graph, {"action": "approve"})
    assert len(writes) == 1 and writes[0]["recommended_action"] == "escalate"
    assert final["disposition"] == "filed"


def test_close_benign_never_reaches_the_gate():
    writes = []
    graph, deps = make([call("describe_principal", name="alice.chen"),
                        call("get_events", event_ids=[SEED]),
                        submit(action="close_benign", verdict="false_positive")], writes)
    out = graph.invoke(initial_state(deps.store, INC), thread_config(INC))
    assert "__interrupt__" not in out and graph.get_state(thread_config(INC)).next == ()
    assert writes == []


def test_the_approver_refuses_any_drift_from_the_approved_ticket():
    """file_ticket's approver is an exact match on the approved arguments."""
    seen = {}

    class Spy(FakeTicketRegistry):
        def dispatch(self, name, arguments):
            seen["ok"] = self.approver(name, dict(arguments))
            seen["drift"] = self.approver(name, {**arguments, "body": "tampered"})
            seen["other_tool"] = self.approver("delete_everything", dict(arguments))
            return super().dispatch(name, arguments)

    deps = bare_deps(lambda inc, ap: Spy(ap, []))
    state = {"incident_id": INC, "human_decision": {"action": "approve", "ticket": PROPOSED}}
    assert file_ticket_node(deps)(state)["disposition"] == "filed"
    assert seen == {"ok": True, "drift": False, "other_tool": False}


def test_file_ticket_without_a_valid_decision_does_nothing():
    writes = []
    deps = bare_deps(lambda inc, ap: FakeTicketRegistry(ap, writes))
    for decision in (None, {}, {"action": "reject", "ticket": None},
                     {"action": "approve", "ticket": None}, {"action": "approve"}):
        state = {"incident_id": INC, "human_decision": decision}
        assert route_after_gate(state) == "end"
        assert file_ticket_node(deps)(state)["disposition"] == "rejected"
    assert writes == []


def test_a_failed_write_is_recorded_not_retried():
    class Boom:
        def dispatch(self, *a):
            raise RuntimeError("outbox unavailable")

    out = file_ticket_node(bare_deps(lambda inc, ap: Boom()))(
        {"incident_id": INC, "human_decision": {"action": "approve", "ticket": PROPOSED}})
    assert out["disposition"] == "failed" and "outbox unavailable" in out["filed_ticket"]["error"]


# --- the real MCP ticket-writer, through the client policy layer ---------------------

def test_approved_ticket_lands_in_the_outbox_via_mcp(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_TICKET_DIR", str(tmp_path))
    store = IncidentStore(ROOT)
    deps = GraphDeps(store=store, client_factory=lambda: ScriptedClient(passing_attempt()),
                     model="scripted", registry_factory=lambda inc, rs: build_registry(store, inc, rs))
    graph = build_graph(deps, MemorySaver())
    graph.invoke(initial_state(store, INC), thread_config(INC))
    assert list(tmp_path.iterdir()) == []
    final = resume(graph, {"action": "edit", "edits": {"title": "Edited via gate"}})
    assert final["disposition"] == "filed" and final["filed_ticket"]["ticket_id"].startswith("TKT-")
    files = list(tmp_path.iterdir())
    assert len(files) == 1
    rec = json.loads(files[0].read_text(encoding="utf-8"))
    assert rec["title"] == "Edited via gate" and rec["incident_id"] == INC
    assert rec["evidence_event_ids"] == [SEED]
