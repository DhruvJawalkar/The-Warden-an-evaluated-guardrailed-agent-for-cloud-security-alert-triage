"""asset-graph MCP server: principal baselines, asset inventory, role trust.

    python -m warden.toolplane.asset_graph       # stdio

describe_principal reads the incident dataset (baselines are dataset-wide, so no incident_id).
describe_asset and describe_trust read the week-2 enrichment tables and are opt-in for the loop
(`--toolset full`); the week-1 toolset exposes describe_principal only.
"""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from warden.loop.tools import DESCRIBE_PRINCIPAL_DESCRIPTION, ToolError, describe_principal_impl
from warden.toolplane.common import READ_ONLY, load_enrichment, store, wire_errors

mcp = FastMCP("warden-asset-graph", mask_error_details=True)

DESCRIBE_ASSET_DESCRIPTION = (
    "Inventory record for a bucket or secret: owning team, data classification, whether public "
    "access is blocked, and who has been granted access. Accepts a bucket name, a secret name or "
    "a full ARN. Use it to judge whether an access is inside or outside the owning team; an asset "
    "with no owner is itself a finding.")

DESCRIBE_TRUST_DESCRIPTION = (
    "Trust policy summary for a role: which identities are expected to assume it and from where. "
    "Use it to tell a routine assumption from one that bypasses the expected path.")


def _asset_key(resource: str) -> str:
    r = (resource or "").strip()
    if r.startswith("arn:aws:s3:::"):
        r = r[len("arn:aws:s3:::"):].split("/")[0]
    elif r.startswith("arn:aws:secretsmanager:"):
        r = r.split(":secret:", 1)[-1]
    elif r.startswith("s3://"):
        r = r[5:].split("/")[0]
    return r


def describe_asset_impl(resource: str) -> dict:
    key = _asset_key(resource)
    assets = load_enrichment("assets.json")["assets"]
    if key not in assets:
        raise ToolError("No inventory record for %r. Known assets: %s"
                        % (resource, ", ".join(sorted(assets))), kind="bad_arguments")
    return {"resource": key, **assets[key]}


def describe_trust_impl(role: str) -> dict:
    trust = load_enrichment("assets.json")["trust"]
    if role not in trust:
        raise ToolError("No trust record for %r. Known roles: %s" % (role, ", ".join(sorted(trust))),
                        kind="bad_arguments")
    return {"role": role, **trust[role]}


@mcp.tool(name="describe_principal", description=DESCRIBE_PRINCIPAL_DESCRIPTION, annotations=READ_ONLY)
@wire_errors
def describe_principal(
    name: Annotated[str, Field(description="Principal name, e.g. svc-ci-deploy")],
) -> dict:
    return describe_principal_impl(store(), name)


@mcp.tool(name="describe_asset", description=DESCRIBE_ASSET_DESCRIPTION, annotations=READ_ONLY)
@wire_errors
def describe_asset(
    resource: Annotated[str, Field(description="Bucket, secret name or ARN, e.g. acme-customer-exports")],
) -> dict:
    return describe_asset_impl(resource)


@mcp.tool(name="describe_trust", description=DESCRIBE_TRUST_DESCRIPTION, annotations=READ_ONLY)
@wire_errors
def describe_trust(
    role: Annotated[str, Field(description="Role name, e.g. svc-ci-deploy")],
) -> dict:
    return describe_trust_impl(role)


if __name__ == "__main__":
    mcp.run(show_banner=False)
