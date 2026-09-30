"""threat-intel MCP server: lookup_asn.

    python -m warden.toolplane.threat_intel      # stdio

Backed by a static synthetic feed (datasets/enrichment_v1/threat_intel.json). The feed is noisy on
purpose; see warden.data.enrichment.
"""

import re
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from warden.loop.tools import ToolError
from warden.toolplane.common import READ_ONLY, load_enrichment, wire_errors

mcp = FastMCP("warden-threat-intel", mask_error_details=True)

LOOKUP_ASN_DESCRIPTION = (
    "Reputation record for a source network (ASN) seen in the logs. Accepts 'AS49505', "
    "'49505' or the log form 'AS49505 Selectel'. Returns reputation, categories and recent "
    "abuse-report volume. Reputation is context, not a verdict: large legitimate networks "
    "carry reports too, and a network with no record is unknown, not safe.")


def lookup_asn_impl(asn: str) -> dict:
    m = re.search(r"(\d{1,10})", asn or "")
    if not m:
        raise ToolError("Could not read an ASN number from %r. Use e.g. 'AS49505'." % (asn,),
                        kind="bad_arguments")
    key = "AS%d" % int(m.group(1))
    entry = load_enrichment("threat_intel.json")["entries"].get(key)
    if entry is None:
        return {"found": False, "asn": key,
                "note": "No record in the feed. Absence is not evidence that the network is benign."}
    return {"found": True, **entry}


@mcp.tool(name="lookup_asn", description=LOOKUP_ASN_DESCRIPTION, annotations=READ_ONLY)
@wire_errors
def lookup_asn(asn: Annotated[str, Field(description="e.g. 'AS49505 Selectel'")]) -> dict:
    return lookup_asn_impl(asn)


if __name__ == "__main__":
    mcp.run(show_banner=False)
