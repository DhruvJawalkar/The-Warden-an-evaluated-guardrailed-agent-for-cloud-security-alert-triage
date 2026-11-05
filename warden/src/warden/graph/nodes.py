"""Graph nodes: plan -> investigate -> verify -> report.

Each node is a function of the checkpointed state. Live objects (client, registry, transcript) are
built inside the node from `GraphDeps` and thrown away at the end, so a process killed mid-node
resumes by re-running that node from the last checkpoint. The week-2 AgentLoop is reused as is.

The report node only *proposes* a ticket. The only path to create_ticket is gate -> file_ticket: the
gate node pauses on `interrupt()` for a human, and file_ticket writes only what a valid approve/edit
decision (checkpointed in state) names, through the client's approval policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from langgraph.types import interrupt

from warden.graph.gate import decide, gate_payload, proposal_for
from warden.graph.state import Observation, WardenState
from warden.graph.verify import verify
from warden.loop.agent_loop import AgentLoop, Budget, build_system_prompt
from warden.loop.tools import IncidentStore
from warden.loop.transcript import RunRecord, Transcript

MAX_VERIFY_RETRIES = 1  # decided 2026-11-05; see docs/week3-notes.md


@dataclass
class GraphDeps:
    """Everything live that nodes need and the checkpoint must not hold."""
    store: IncidentStore
    client_factory: Callable[[], Any]
    registry_factory: Callable[[str, dict], Any]  # (incident_id, run_state) -> registry
    model: str
    prompt_version: str = "v2"
    max_steps: int = 25
    max_usd: float = 0.50  # per incident, across every investigate attempt
    max_verify_retries: int = MAX_VERIFY_RETRIES
    compaction: str = "elide"  # "summarise" turns on summarising compaction (week-6 ablation flag)
    run_dir: Optional[str] = None  # when set, each investigate attempt saves its RunRecord
    # (incident_id, approver) -> a started registry holding create_ticket. None = real MCP ticket-writer.
    ticket_registry_factory: Optional[Callable[[str, Callable], Any]] = None


def plan_node(deps: GraphDeps):
    def plan(state: WardenState) -> dict:
        """Deterministic: investigation questions from the alert alone. No model call, no dataset
        read beyond the alert, so it costs nothing and cannot leak the answer key."""
        alert = state["alert"]
        who = alert.get("primary_principal")
        qs = [
            "What is normal for %s (region, source network, actions, resources)?" % who,
            "Does the alerting activity deviate from that baseline in any one dimension?",
            "What else did %s do in the window, including writes?" % who,
            "Who else touched the same resources, and was the change that enabled this made by "
            "someone other than %s?" % who,
        ]
        return {"plan": qs}
    return plan


def _task_message(alert: dict, plan: list, gaps: list, prior: Optional[dict]) -> str:
    msg = "Triage alert %s. Investigate, then submit your verdict." % alert["alert_id"]
    if plan:
        msg += "\n\nQuestions to answer:\n" + "\n".join("- " + q for q in plan)
    if gaps:
        msg += ("\n\nA reviewer checked your previous attempt and found gaps. Address each, then "
                "submit a corrected verdict. Re-fetch with get_events any event you cite.\n"
                + "\n".join("- " + g["instruction"] for g in gaps))
        if prior:
            msg += "\n\nPrevious verdict, for reference: %s / %s, citing %s." % (
                prior.get("verdict"), prior.get("recommended_action"),
                ", ".join(prior.get("evidence_event_ids") or []))
    return msg


def _observations(run: RunRecord) -> list:
    out = []
    for step in run.steps:
        for call, res in zip(step.tool_calls, step.tool_results):
            out.append(Observation(tool=call.name, arguments=dict(call.arguments),
                                   is_error=res.is_error,
                                   payload=None if res.is_error else res.payload))
    return out


def investigate_node(deps: GraphDeps):
    def investigate(state: WardenState) -> dict:
        spent = state.get("cost_usd", 0.0)
        remaining = deps.max_usd - spent
        if remaining <= 0:
            return {"stop_cause": "max_usd"}
        alert = state["alert"]
        run_state: dict = {}
        registry = deps.registry_factory(state["incident_id"], run_state)
        try:
            transcript = Transcript(build_system_prompt(alert, registry.names(), deps.prompt_version))
            transcript.add_user(_task_message(alert, state.get("plan", []), state.get("gaps", []),
                                              state.get("verdict")))
            run = RunRecord.new(state["incident_id"], deps.model)
            run.prompt_version = deps.prompt_version
            loop = AgentLoop(deps.client_factory(), registry, transcript,
                             Budget(max_steps=deps.max_steps, max_usd=remaining), run, run_state,
                             compaction=deps.compaction)
            try:
                loop.run_until_done()
            finally:
                if deps.run_dir and (run.steps or run.stop_cause):
                    run.save(deps.run_dir)
        finally:
            if hasattr(registry, "close"):
                registry.close()
        return {
            "observations": _observations(run),
            # a retry that fails to submit must not erase the earlier proposal
            "verdict": run_state.get("verdict") or state.get("verdict"),
            "cost_usd": run.total_cost_usd,
            "stop_cause": run.stop_cause,
        }
    return investigate


def verify_node(deps: GraphDeps):
    def verify_(state: WardenState) -> dict:
        verdict = state.get("verdict")
        attempts = state.get("verify_attempts", 0) + 1
        if not verdict:
            return {"gaps": [], "verify_attempts": attempts}
        return {"gaps": verify(state["alert"], verdict, state.get("observations", [])),
                "verify_attempts": attempts}
    return verify_


def route_after_verify(deps: GraphDeps):
    def route(state: WardenState) -> str:
        if not state.get("verdict"):
            return "report"
        if state.get("gaps") and state.get("verify_attempts", 0) <= deps.max_verify_retries \
                and state.get("cost_usd", 0.0) < deps.max_usd:
            return "investigate"
        return "report"
    return route


def report_node(deps: GraphDeps):
    def report(state: WardenState) -> dict:
        """Assemble the outcome. Three statuses, kept distinct for the eval: verified (all checks
        passed), unverified (checks still failing after the retry), unresolved (no verdict)."""
        verdict, gaps = state.get("verdict"), state.get("gaps") or []
        status = "unresolved" if not verdict else ("unverified" if gaps else "verified")
        ticket = proposal_for(state)
        return {
            "ticket": ticket,
            "disposition": "none" if ticket is None else "pending_decision",
            "report": {"status": status, "verdict": verdict,
                       "gaps": [g["detail"] for g in gaps],
                       "stop_cause": state.get("stop_cause", ""),
                       "verify_attempts": state.get("verify_attempts", 0),
                       "cost_usd": round(state.get("cost_usd", 0.0), 6)},
        }
    return report


def route_after_report(state: WardenState) -> str:
    return "gate" if state.get("ticket") else "end"


def gate_node(deps: GraphDeps):
    def gate(state: WardenState) -> dict:
        """Pause for a human. LangGraph re-runs this node from the top on resume, so everything
        before interrupt() must be (and is) side-effect free; the write lives in file_ticket."""
        proposed = state["ticket"]
        raw = interrupt(gate_payload(state, proposed))
        decision = decide(raw, proposed)
        return {"human_decision": decision,
                "disposition": "rejected" if decision["action"] == "reject" else "approved"}
    return gate


def route_after_gate(state: WardenState) -> str:
    d = state.get("human_decision") or {}
    # Fail closed: only an explicit, recorded approve/edit with a ticket reaches the write step.
    return "file_ticket" if d.get("action") in ("approve", "edit") and d.get("ticket") else "end"


def _open_ticket_registry(deps: GraphDeps, incident_id: str, approver: Callable):
    if deps.ticket_registry_factory:
        return deps.ticket_registry_factory(incident_id, approver)
    from warden.toolplane.client import McpRegistry
    return McpRegistry(incident_id, {}, dataset=deps.store.root, toolset="ticket",
                       approver=approver).start()


def file_ticket_node(deps: GraphDeps):
    def file_ticket(state: WardenState) -> dict:
        """Write the approved ticket. The client's approver accepts exactly the approved arguments
        and nothing else, so a drifted payload is refused by the same policy layer as before. The
        ticket id is a hash of (incident, title): re-running after a crash overwrites, never dups."""
        d = state.get("human_decision") or {}
        approved = d.get("ticket")
        if d.get("action") not in ("approve", "edit") or not approved:
            return {"disposition": "rejected"}
        args = {k: approved[k] for k in ("title", "severity", "recommended_action", "body",
                                         "evidence_event_ids")}
        registry = _open_ticket_registry(
            deps, state["incident_id"], lambda name, a: name == "create_ticket" and dict(a) == args)
        try:
            payload, _ = registry.dispatch("create_ticket", dict(args))
        except Exception as exc:  # noqa: BLE001 - a failed write is recorded, never retried blind
            return {"disposition": "failed", "filed_ticket": {"error": str(exc)[:300]}}
        finally:
            if hasattr(registry, "close"):
                registry.close()
        return {"disposition": "filed", "filed_ticket": payload}
    return file_ticket
