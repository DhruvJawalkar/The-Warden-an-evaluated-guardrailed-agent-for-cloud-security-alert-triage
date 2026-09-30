"""Helpers shared by every Warden MCP server.

Do not `print()` in a server: on stdio, stdout IS the JSON-RPC channel and a stray line
corrupts the session. Log to stderr.
"""

import functools
import os
import re
from typing import Optional

from fastmcp.exceptions import ToolError as WireToolError

from warden.loop.tools import IncidentStore, ToolError

# A model-visible failure crosses the wire as "[kind] message". Anything that reaches the
# client WITHOUT that prefix is a server bug (masked by mask_error_details) and crashes the run.
KIND_PREFIX = re.compile(r"^\[(?P<kind>[a-z_]+)\] (?P<msg>.*)$", re.DOTALL)

_stores: dict = {}

# Every tool must declare its annotations. The client FAILS CLOSED: a tool that does not say it is
# read-only is treated as a write and cannot run without approval.
READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True,
             "openWorldHint": False}
WRITE_IDEMPOTENT = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,
                    "openWorldHint": False}

_json_cache: dict = {}


def dataset_root() -> str:
    return os.path.abspath(os.environ.get("WARDEN_DATASET", "datasets/v1"))


def enrichment_root() -> str:
    return os.path.abspath(os.environ.get("WARDEN_ENRICHMENT", "datasets/enrichment_v1"))


def load_enrichment(filename: str) -> dict:
    """Read-only enrichment table (threat intel, assets). A cache, not session state."""
    import json
    path = os.path.join(enrichment_root(), filename)
    if path not in _json_cache:
        with open(path, encoding="utf-8") as fh:
            _json_cache[path] = json.load(fh)
    return _json_cache[path]


def store() -> IncidentStore:
    """Read-only view of the dataset. A cache, not session state: safe to lose or duplicate."""
    root = dataset_root()
    if root not in _stores:
        _stores[root] = IncidentStore(root)
    return _stores[root]


def wire_errors(fn):
    """Translate warden ToolError (model-visible) into an MCP tool error carrying its kind."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ToolError as exc:
            raise WireToolError("[%s] %s" % (exc.kind, exc)) from None

    return wrapper


def parse_wire_error(text: str) -> Optional[tuple]:
    m = KIND_PREFIX.match(text or "")
    return (m.group("kind"), m.group("msg")) if m else None
