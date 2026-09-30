"""log-search MCP server: search_logs, get_events.

    python -m warden.toolplane.log_search        # stdio

Stateless: `incident_id` is an explicit argument on every call. The loop's client binds it and
hides it from the model, so the model can neither see nor override which incident it reads.
NOTE: no `from __future__ import annotations` here; FastMCP builds the schema from real
annotations, and the wire_errors wrapper lives in another module.
"""

from typing import Annotated, Optional

from fastmcp import FastMCP
from pydantic import Field

from warden.loop.tools import (
    GET_EVENTS_DESCRIPTION, SEARCH_LOGS_DESCRIPTION, get_events_impl, search_logs_impl,
)
from warden.toolplane.common import READ_ONLY, store, wire_errors

mcp = FastMCP("warden-log-search", mask_error_details=True)


def _s(desc: Optional[str] = None):
    return Field(description=desc) if desc else Field()


@mcp.tool(name="search_logs", description=SEARCH_LOGS_DESCRIPTION, annotations=READ_ONLY)
@wire_errors
def search_logs(
    incident_id: str,
    principal_name: Annotated[Optional[str], _s("Exact principal, e.g. alice.chen")] = None,
    event_name: Annotated[Optional[str], _s("Exact API action, e.g. GetObject")] = None,
    event_source: Annotated[Optional[str], _s("e.g. s3.amazonaws.com")] = None,
    aws_region: Annotated[Optional[str], _s()] = None,
    source_ip: Annotated[Optional[str], _s()] = None,
    source_asn: Annotated[Optional[str], _s("e.g. 'AS14618 Amazon'")] = None,
    time_from: Annotated[Optional[str], _s("ISO-8601 Z, inclusive lower bound")] = None,
    time_to: Annotated[Optional[str], _s("ISO-8601 Z, inclusive upper bound")] = None,
    errors_only: Annotated[Optional[bool], _s("Only events with an error_code")] = None,
    writes_only: Annotated[Optional[bool], _s("Only mutating (non read-only) events")] = None,
    contains: Annotated[Optional[str], _s("Substring over params/resources")] = None,
    limit: Annotated[int, _s("Max rows, 1-100. Default 25.")] = 25,
) -> dict:
    filters = {k: v for k, v in dict(
        principal_name=principal_name, event_name=event_name, event_source=event_source,
        aws_region=aws_region, source_ip=source_ip, source_asn=source_asn, time_from=time_from,
        time_to=time_to, errors_only=errors_only, writes_only=writes_only, contains=contains,
    ).items() if v is not None}
    return search_logs_impl(store(), incident_id, limit, **filters)


@mcp.tool(name="get_events", description=GET_EVENTS_DESCRIPTION, annotations=READ_ONLY)
@wire_errors
def get_events(
    incident_id: str,
    event_ids: Annotated[list[str], _s("1-20 event_id strings")],
) -> dict:
    return get_events_impl(store(), incident_id, event_ids)


if __name__ == "__main__":
    mcp.run(show_banner=False)
