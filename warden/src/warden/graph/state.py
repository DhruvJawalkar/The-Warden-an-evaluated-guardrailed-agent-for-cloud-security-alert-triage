"""Graph state schema.

Every superstep is checkpointed to Postgres, so state holds only JSON-serialisable values and only
what a resumed process cannot recompute: the alert, the plan, what the agent has observed, the
verdict, the verifier's gaps, and spend. Live objects (the Anthropic client, MCP sessions, the
Transcript) are rebuilt on resume from `observations` and are NOT in state.

Reducers: a key with an `Annotated[..., reducer]` merges concurrent/repeated writes with that
function. A key without one is overwritten by the latest write.
"""

from __future__ import annotations

import operator
from typing import Annotated, Optional, TypedDict


def keep_max(a: int, b: int) -> int:
    return max(a or 0, b or 0)


class Observation(TypedDict):
    """One tool call and its outcome, in the form the verifier needs. Payloads of get_events are
    kept whole (full records); other payloads are kept as returned. Errors carry no payload."""
    tool: str
    arguments: dict
    is_error: bool
    payload: Optional[dict]


class Gap(TypedDict):
    check: str        # which deterministic/LLM check raised it
    detail: str       # what is missing, for the report and the eval
    instruction: str  # what investigate is told to do about it


class WardenState(TypedDict, total=False):
    # inputs (written once)
    incident_id: str
    alert: dict
    # plan node
    plan: list                                          # investigation questions, strings
    # investigate node (append-only: a retry adds observations, never rewrites history)
    observations: Annotated[list, operator.add]
    # verify node
    verdict: Optional[dict]                             # the proposed verdict, overwritten per attempt
    gaps: list                                          # latest verifier gaps; empty means passed
    verify_attempts: Annotated[int, keep_max]
    llm_verify_calls: Annotated[int, keep_max]          # hard-capped at 1 per incident
    # report / gate
    ticket: Optional[dict]                              # a proposal only; the gate decides if it is filed
    report: dict                                        # final outcome: status, verdict, gaps, cost
    human_decision: Optional[dict]                      # {"action": approve|reject|edit, "ticket", "reason", "reviewer"}
    filed_ticket: Optional[dict]                        # create_ticket's result, only after approve/edit
    disposition: str                                    # none (no ticket proposed) | pending_decision | approved (decision recorded, write pending) | filed | rejected | failed
    # accounting
    cost_usd: Annotated[float, operator.add]
    stop_cause: str
