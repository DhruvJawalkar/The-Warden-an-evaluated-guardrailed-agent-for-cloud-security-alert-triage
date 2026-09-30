"""MCP-backed drop-in for ToolRegistry.

AgentLoop only touches names() / schemas() / dispatch(); this class provides the same three over
FastMCP servers spoken to through stdio, so the loop is unchanged.

What lives here on purpose (client side, not on any server):
  * `incident_id` binding. Servers are stateless and take it as an argument; the client injects
    it and hides it from the model-facing schema. The model cannot name another incident, which
    is exactly the cross-incident read a poisoned log line would try to steer it into.
  * `submit_verdict`. It is loop control, and it needs the set of event_ids the client has seen
    returned by get_events, which is client state by definition.
  * Unknown-argument rejection. FastMCP rejects undeclared arguments too, but with a pydantic
    dump; we reject first with a message the model can act on.
The loop is synchronous, so the async client runs on one background event loop for the whole run.
"""

import asyncio
import concurrent.futures
import json
import os
import re
import sys
import threading
import time
from contextlib import AsyncExitStack
from typing import Callable, Optional

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from warden.loop.tools import ToolError, ToolRegistry, make_submit_verdict_tool
from warden.toolplane.common import parse_wire_error

ALL_SERVERS = {
    "log-search": "warden.toolplane.log_search",
    "asset-graph": "warden.toolplane.asset_graph",
    "threat-intel": "warden.toolplane.threat_intel",
    "ticket-writer": "warden.toolplane.ticket_writer",
    "runbook-rag": "warden.toolplane.runbook_rag",
}

# A toolset is the set of tools the MODEL is offered, and it is a policy decision, not a discovery
# result. "w1" is exactly the week-1 tool surface, so porting to MCP changes one variable (the
# transport). New tools change the system prompt and the task's difficulty; they are opt-in.
TOOLSETS = {
    "w1": {"servers": ("log-search", "asset-graph"),
           "allow": ("search_logs", "get_events", "describe_principal")},
    "full": {"servers": tuple(ALL_SERVERS), "allow": None},
}
DEFAULT_TOOLSET = "w1"

# Model-facing order. In-process registration order is search_logs, get_events,
# describe_principal, submit_verdict; keep it so tool order is not a hidden variable.
TOOL_ORDER = ("search_logs", "get_events", "describe_principal")
HIDDEN_ARGS = ("incident_id",)


def _clean(v: dict) -> dict:
    v = {k: x for k, x in v.items() if k not in ("title", "default")}
    if "anyOf" in v:
        non_null = [x for x in v["anyOf"] if x.get("type") != "null"]
        if len(non_null) == 1:
            merged = dict(non_null[0])
            merged.update({k: x for k, x in v.items() if k != "anyOf"})
            return _clean(merged)
    if isinstance(v.get("items"), dict):
        v["items"] = _clean(v["items"])
    return v


def model_schema(input_schema: dict, hidden: tuple = HIDDEN_ARGS) -> dict:
    """Server schema -> the schema shown to the model: hidden args removed, pydantic noise
    (title/default/anyOf-null) stripped, so it matches the hand-written in-process schema."""
    props = {k: _clean(v) for k, v in input_schema.get("properties", {}).items() if k not in hidden}
    required = [r for r in input_schema.get("required", []) if r not in hidden]
    return {"type": "object", "properties": props, "required": required}


def is_read_only(tool) -> bool:
    """Fail closed: a tool that does not affirmatively declare readOnlyHint=True is a write."""
    ann = getattr(tool, "annotations", None)
    if ann is None:
        return False
    if isinstance(ann, dict):
        data = ann
    else:
        data = ann.model_dump() if hasattr(ann, "model_dump") else vars(ann)
    return (data.get("readOnlyHint", data.get("read_only_hint"))) is True


_VALIDATION_ERR = re.compile(r"validation error", re.I)


def _clean_validation(tool: str, text: str) -> str:
    """Boil a pydantic dump down to 'arg: reason' lines. Never echoes input values."""
    lines = [ln.strip() for ln in text.splitlines()]
    out, arg = [], None
    for ln in lines:
        if not ln or ln.startswith("For further information") or _VALIDATION_ERR.search(ln):
            continue
        if re.match(r"^[A-Za-z_][\w.\[\]]*$", ln):
            arg = ln
            continue
        reason = re.sub(r"\s*\[type=.*$", "", ln)
        out.append("%s: %s" % (arg, reason) if arg else reason)
    return "Invalid arguments for %s: %s" % (tool, "; ".join(out) or "validation failed")


class McpRegistry:
    """Same surface as ToolRegistry, backed by stdio MCP servers."""

    def __init__(self, incident_id: str, run_state: dict, dataset: Optional[str] = None,
                 toolset: str = DEFAULT_TOOLSET, approver: Optional[Callable] = None,
                 call_timeout: float = 60.0, startup_timeout: float = 60.0):
        if toolset not in TOOLSETS:
            raise ValueError("unknown toolset %r (have: %s)" % (toolset, ", ".join(TOOLSETS)))
        self.incident_id = incident_id
        self.dataset = os.path.abspath(dataset or os.environ.get("WARDEN_DATASET", "datasets/v1"))
        self.toolset = toolset
        self.servers = {n: ALL_SERVERS[n] for n in TOOLSETS[toolset]["servers"]}
        self.allow = TOOLSETS[toolset]["allow"]
        # approver(tool_name, arguments) -> bool. None means "deny every write". Week 3 replaces
        # this callback with a LangGraph interrupt.
        self.approver = approver
        self.call_timeout = call_timeout
        self.startup_timeout = startup_timeout
        self.fetched: set = set()
        self._local = ToolRegistry()
        self._local.add(make_submit_verdict_tool(run_state, self.fetched))
        self._remote: dict = {}  # tool name -> (server name, Client, mcp Tool)
        self._loop = None
        self._thread = None
        self._owner = None
        self._stop = None

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> "McpRegistry":
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True,
                                        name="warden-mcp-loop")
        self._thread.start()
        ready: concurrent.futures.Future = concurrent.futures.Future()
        self._owner = asyncio.run_coroutine_threadsafe(self._own(ready), self._loop)
        try:
            ready.result(timeout=self.startup_timeout)
        except BaseException:
            self.close()
            raise
        return self

    async def _own(self, ready: concurrent.futures.Future) -> None:
        """Owns every session for the run, so each opens and closes in the same task."""
        self._stop = asyncio.Event()
        env = dict(os.environ)
        env["WARDEN_DATASET"] = self.dataset
        # Servers inherit our cwd today, but a relative path is a trap the day that changes.
        for var, default in (("WARDEN_ENRICHMENT", "datasets/enrichment_v1"),
                             ("WARDEN_RUNBOOKS", "datasets/runbooks_v1"),
                             ("WARDEN_TICKET_DIR", "tickets")):
            env[var] = os.path.abspath(os.environ.get(var, default))
        try:
            async with AsyncExitStack() as stack:
                for server_name, module in self.servers.items():
                    transport = StdioTransport(command=sys.executable, args=["-m", module], env=env)
                    client = Client(transport)
                    await stack.enter_async_context(client)
                    for tool in await client.list_tools():
                        if tool.name in self._remote or self._local_has(tool.name):
                            raise RuntimeError("tool name collision: %s" % tool.name)
                        self._remote[tool.name] = (server_name, client, tool)
                if self.allow is not None:
                    missing = set(self.allow) - set(self._remote)
                    if missing:
                        raise RuntimeError("toolset %r expects tools no server offers: %s"
                                           % (self.toolset, ", ".join(sorted(missing))))
                    self._remote = {n: v for n, v in self._remote.items() if n in self.allow}
                ready.set_result(None)
                await self._stop.wait()
        except BaseException as exc:  # noqa: BLE001
            if not ready.done():
                ready.set_exception(exc)
            else:
                raise

    def _local_has(self, name: str) -> bool:
        return name in self._local.names()

    def close(self) -> None:
        if self._loop is None:
            return
        try:
            if self._stop is not None:
                self._loop.call_soon_threadsafe(self._stop.set)
            if self._owner is not None:
                try:
                    self._owner.result(timeout=15)
                except Exception:  # noqa: BLE001 - shutdown must not mask the run's own error
                    pass
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)
            self._loop = None

    def __enter__(self) -> "McpRegistry":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()

    # --- the ToolRegistry surface ---------------------------------------------

    def names(self) -> list:
        return sorted(set(self._remote) | set(self._local.names()))

    def server_of(self, name: str) -> str:
        return self._remote[name][0] if name in self._remote else "client"

    def schemas(self) -> list:
        out = []
        ordered = [n for n in TOOL_ORDER if n in self._remote]
        ordered += sorted(n for n in self._remote if n not in TOOL_ORDER)
        for name in ordered:
            _, _, tool = self._remote[name]
            out.append({"name": name, "description": tool.description or "",
                        "input_schema": model_schema(_input_schema(tool))})
        out.extend(self._local.schemas())
        return out

    def dispatch(self, name: str, arguments: dict):
        """Returns (payload, latency_ms). Raises ToolError for model-visible failures."""
        if self._local_has(name):
            return self._local.dispatch(name, arguments)
        if name not in self._remote:
            raise ToolError("Unknown tool %r. Available: %s" % (name, ", ".join(self.names())),
                            kind="unknown_tool")
        _, client, tool = self._remote[name]
        visible = set(model_schema(_input_schema(tool))["properties"])
        unknown = set(arguments) - visible
        if unknown:
            raise ToolError("Unknown argument(s) for %s: %s. Allowed: %s"
                            % (name, ", ".join(sorted(unknown)), ", ".join(sorted(visible))),
                            kind="bad_arguments")
        if not is_read_only(tool) and not (self.approver and self.approver(name, dict(arguments))):
            raise ToolError("%s changes state and requires human approval, which was not granted. "
                            "Do not retry; describe the action you would take in your rationale."
                            % name, kind="approval_required")
        args = dict(arguments)
        if "incident_id" in _input_schema(tool).get("properties", {}):
            args["incident_id"] = self.incident_id

        t0 = time.time()
        result = self._call(client, name, args)
        latency = int((time.time() - t0) * 1000)
        text = "".join(getattr(c, "text", "") for c in result.content)
        if result.is_error:
            parsed = parse_wire_error(text)
            if parsed:
                raise ToolError(parsed[1], kind=parsed[0])
            if _VALIDATION_ERR.search(text):
                raise ToolError(_clean_validation(name, text), kind="bad_arguments")
            # No kind prefix and not validation: a server bug. Crash the run, like a bug in-process.
            raise RuntimeError("MCP server error from %s: %s" % (name, text[:300]))
        payload = result.structured_content
        if payload is None:
            payload = json.loads(text) if text else None
        if name == "get_events" and isinstance(arguments.get("event_ids"), list):
            self.fetched.update(arguments["event_ids"])
        return payload, latency

    def _call(self, client, name: str, args: dict):
        fut = asyncio.run_coroutine_threadsafe(
            client.call_tool(name, args, raise_on_error=False), self._loop)
        try:
            return fut.result(timeout=self.call_timeout)
        except concurrent.futures.TimeoutError:
            fut.cancel()
            raise RuntimeError("MCP call %s timed out after %.0fs" % (name, self.call_timeout))


def _input_schema(tool) -> dict:
    return getattr(tool, "input_schema", None) or tool.inputSchema


def open_registry(kind: str, store, incident_id: str, run_state: dict, dataset: Optional[str] = None,
                  toolset: str = DEFAULT_TOOLSET):
    """kind='inproc' -> the week-1 registry; kind='mcp' -> FastMCP servers over stdio."""
    if kind == "inproc":
        if toolset != "w1":
            raise ValueError("the in-process registry only implements toolset 'w1'")
        from warden.loop.tools import build_registry
        return build_registry(store, incident_id, run_state)
    if kind == "mcp":
        return McpRegistry(incident_id, run_state, dataset=dataset, toolset=toolset).start()
    raise ValueError("unknown tools kind %r" % kind)
