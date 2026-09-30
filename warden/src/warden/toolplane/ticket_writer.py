"""ticket-writer MCP server: create_ticket. The only write tool in the tool plane.

    python -m warden.toolplane.ticket_writer     # stdio

Gating lives in the CLIENT policy layer (McpRegistry.approver), not here: this tool declares
readOnlyHint=False and the client refuses to run any non-read-only tool without approval. Week 3
replaces the approver callback with a LangGraph interrupt.

Stateless and idempotent: the ticket id is a hash of (incident_id, title), so a retry after a timeout
overwrites the same file instead of filing a duplicate. Tickets go to an outbox directory, never to
a real system.
"""

import hashlib
import json
import os
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from warden.loop.tools import ACTIONS, SEVERITIES, ToolError
from warden.toolplane.common import WRITE_IDEMPOTENT, wire_errors

mcp = FastMCP("warden-ticket-writer", mask_error_details=True)

CREATE_TICKET_DESCRIPTION = (
    "File a ticket in the security queue for a human to act on. This is a write action and needs "
    "analyst approval before it runs. State the verdict, the recommended action and the event ids "
    "that support it.")


def outbox() -> str:
    return os.path.abspath(os.environ.get("WARDEN_TICKET_DIR", "tickets"))


def create_ticket_impl(incident_id: str, title: str, severity: str, recommended_action: str,
                       body: str, evidence_event_ids: list) -> dict:
    errs = []
    if severity not in SEVERITIES:
        errs.append("severity must be one of %s" % (SEVERITIES,))
    if recommended_action not in ACTIONS:
        errs.append("recommended_action must be one of %s" % (ACTIONS,))
    if not title or len(title) > 200:
        errs.append("title must be 1-200 characters")
    if not evidence_event_ids:
        errs.append("evidence_event_ids must not be empty")
    if errs:
        raise ToolError("; ".join(errs), kind="bad_arguments")
    ticket_id = "TKT-" + hashlib.sha1(("%s|%s" % (incident_id, title)).encode("utf-8")).hexdigest()[:8]
    record = {"ticket_id": ticket_id, "incident_id": incident_id, "title": title, "severity": severity,
              "recommended_action": recommended_action, "body": body,
              "evidence_event_ids": evidence_event_ids, "status": "open"}
    os.makedirs(outbox(), exist_ok=True)
    with open(os.path.join(outbox(), ticket_id + ".json"), "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2)
    return {"ticket_id": ticket_id, "status": "open"}


@mcp.tool(name="create_ticket", description=CREATE_TICKET_DESCRIPTION, annotations=WRITE_IDEMPOTENT)
@wire_errors
def create_ticket(
    incident_id: str,
    title: Annotated[str, Field(description="One-line summary, max 200 chars")],
    severity: Annotated[str, Field(description="critical | high | medium | low | informational")],
    recommended_action: Annotated[str, Field(description="escalate | contain | close_benign | monitor")],
    body: Annotated[str, Field(description="Findings and reasoning, referencing events by id")],
    evidence_event_ids: Annotated[list[str], Field(description="Event ids that support the ticket")],
) -> dict:
    return create_ticket_impl(incident_id, title, severity, recommended_action, body, evidence_event_ids)


if __name__ == "__main__":
    mcp.run(show_banner=False)
