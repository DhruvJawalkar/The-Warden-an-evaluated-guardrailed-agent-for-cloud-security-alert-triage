"""Human approval gate: what is shown, and how a reply is read. Pure functions, no I/O.

The gate fails closed. Anything that is not an exact, well-formed approve / edit / reject is a
reject, with the reason recorded. There is no default-approve path, no timeout-approve path, and
an edit that touches anything outside EDITABLE (or breaks create_ticket's own rules) is a reject
of the whole reply rather than a partial edit.

Resume value (what `Command(resume=...)` carries):
    {"action": "approve"}
    {"action": "reject", "reason": "..."}
    {"action": "edit", "edits": {"title": ..., "severity": ..., "recommended_action": ..., "body": ...}}
each optionally with "reviewer": "<name>".
"""

from __future__ import annotations

from typing import Optional

from warden.data.schema import ACTIONS, SEVERITIES

EDITABLE = ("title", "severity", "recommended_action", "body")
TICKET_KEYS = ("title", "severity", "recommended_action", "body", "evidence_event_ids")
ACTIONS_OK = ("approve", "edit", "reject")


def proposal_for(state: dict) -> Optional[dict]:
    """The ticket the agent proposes. A containing/escalating verdict proposes its own ticket. A run
    with no verdict (budget spent, stalled) proposes an escalation built from the alert alone, so
    "unresolved" becomes a human decision instead of a silent drop. None means nothing to approve."""
    verdict, alert = state.get("verdict"), state["alert"]
    if verdict:
        if verdict["recommended_action"] not in ("contain", "escalate"):
            return None
        return {
            "title": ("%s: %s" % (alert.get("rule_name", "alert"), alert.get("primary_principal")))[:200],
            "severity": verdict["severity"],
            "recommended_action": verdict["recommended_action"],
            "body": verdict["rationale"],
            "evidence_event_ids": list(verdict["evidence_event_ids"]),
        }
    seeds = list(alert.get("seed_event_ids") or [])
    if not seeds:
        return None  # create_ticket requires evidence; with none there is nothing it could file
    sev = alert.get("severity_reported")
    return {
        "title": ("UNRESOLVED: %s: %s" % (alert.get("rule_name", "alert"),
                                          alert.get("primary_principal")))[:200],
        "severity": sev if sev in SEVERITIES else "medium",
        "recommended_action": "escalate",
        "body": "The agent did not reach a verdict (stop cause: %s). Needs analyst triage. "
                "Evidence listed is the alert's own seed events, not agent findings."
                % (state.get("stop_cause") or "unknown"),
        "evidence_event_ids": seeds,
    }


def gate_payload(state: dict, ticket: dict) -> dict:
    """What the reviewer sees. Plain data, so any front end can render it."""
    report = state.get("report") or {}
    return {
        "kind": "unresolved" if not state.get("verdict") else "proposed_ticket",
        "incident_id": state["incident_id"],
        "ticket": ticket,
        "agent_status": report.get("status"),
        "open_gaps": report.get("gaps", []),
        "stop_cause": state.get("stop_cause", ""),
        "allowed": {"actions": list(ACTIONS_OK), "editable": list(EDITABLE)},
    }


def _reject(reason: str, reviewer: str = "") -> dict:
    return {"action": "reject", "ticket": None, "reason": reason, "reviewer": reviewer}


def decide(raw, proposed: dict) -> dict:
    """Turn whatever came back from the human into {"action", "ticket", "reason", "reviewer"}.
    `ticket` is the exact ticket to file, or None. Never raises."""
    if not isinstance(raw, dict):
        return _reject("invalid_resume: reply is not an object")
    reviewer = raw.get("reviewer") if isinstance(raw.get("reviewer"), str) else ""
    action = raw.get("action")
    if action not in ACTIONS_OK:
        return _reject("invalid_resume: unknown action %r" % (action if isinstance(action, str) else "?"),
                       reviewer)
    if action == "reject":
        reason = raw.get("reason")
        return _reject(reason if isinstance(reason, str) and reason else "rejected", reviewer)
    if action == "approve":
        if set(raw) - {"action", "reviewer"}:
            return _reject("invalid_resume: approve takes no other fields (use edit)", reviewer)
        return {"action": "approve", "ticket": dict(proposed), "reason": "", "reviewer": reviewer}

    # edit
    edits = raw.get("edits")
    if set(raw) - {"action", "edits", "reviewer"} or not isinstance(edits, dict) or not edits:
        return _reject("invalid_resume: edit needs a non-empty 'edits' object and nothing else", reviewer)
    bad = sorted(set(edits) - set(EDITABLE))
    if bad:
        return _reject("invalid_resume: not editable: %s" % ", ".join(map(str, bad)), reviewer)
    ticket = {**proposed, **edits}
    err = _ticket_error(ticket)
    if err:
        return _reject("invalid_resume: " + err, reviewer)
    return {"action": "edit", "ticket": ticket, "reason": "", "reviewer": reviewer}


def _ticket_error(t: dict) -> Optional[str]:
    if not isinstance(t.get("title"), str) or not 1 <= len(t["title"]) <= 200:
        return "title must be 1-200 characters"
    if t.get("severity") not in SEVERITIES:
        return "severity must be one of %s" % (SEVERITIES,)
    if t.get("recommended_action") not in ACTIONS:
        return "recommended_action must be one of %s" % (ACTIONS,)
    if not isinstance(t.get("body"), str) or not t["body"].strip():
        return "body must be non-empty text"
    return None
