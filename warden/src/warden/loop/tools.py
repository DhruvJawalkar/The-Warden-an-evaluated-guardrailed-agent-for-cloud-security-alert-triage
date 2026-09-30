"""Week-1 tool plane: plain Python over the generated dataset.

In week 2 every one of these becomes a FastMCP server and this module becomes a
thin client. The signatures are chosen now so that port is mechanical — note
that each tool takes only JSON-serialisable arguments and returns only
JSON-serialisable payloads. Nothing here holds a session; that is the
2026-07-28 stateless posture, adopted early on purpose.

Tools return NATIVE OBJECTS, not strings. Turning a payload into transcript
text is a context-budget decision and belongs to the loop, not the tool.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from warden.data.schema import ACTIONS, SEVERITIES, VERDICTS, read_jsonl


class ToolError(Exception):
    """A failure the MODEL should see and can act on (bad filter, no results,
    unknown principal). Distinct from a bug, which should crash the run."""

    def __init__(self, message: str, kind: str = "tool_failed"):
        super().__init__(message)
        self.kind = kind


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict
    fn: Callable
    is_terminal: bool = False
    mutates: bool = False


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict = {}

    def add(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise ToolError(
                "Unknown tool %r. Available: %s" % (name, ", ".join(sorted(self._tools))),
                kind="unknown_tool",
            )
        return self._tools[name]

    def names(self) -> list:
        return sorted(self._tools)

    def schemas(self) -> list:
        return [{"name": t.name, "description": t.description, "input_schema": t.input_schema}
                for t in self._tools.values()]

    def dispatch(self, name: str, arguments: dict):
        """Returns (payload, latency_ms). Raises ToolError for model-visible failures."""
        tool = self.get(name)
        t0 = time.time()
        try:
            payload = tool.fn(**arguments)
        except ToolError:
            raise
        except TypeError as exc:
            raise ToolError("Invalid arguments for %s: %s" % (name, exc), kind="bad_arguments")
        return payload, int((time.time() - t0) * 1000)


# --- dataset access ----------------------------------------------------------

class IncidentStore:
    """Read-only view of one dataset version. Ground truth is NEVER loaded here."""

    def __init__(self, root: str = "datasets/v1"):
        self.root = root
        with open(os.path.join(root, "principals.json"), encoding="utf-8") as fh:
            self.principals = json.load(fh)
        self._events_cache: dict = {}

    def alert(self, incident_id: str) -> dict:
        path = os.path.join(self.root, "alerts", "%s.json" % incident_id)
        if not os.path.exists(path):
            raise ToolError("No such incident: %s" % incident_id, kind="bad_arguments")
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def events(self, incident_id: str) -> list:
        if incident_id not in self._events_cache:
            self._events_cache[incident_id] = read_jsonl(
                os.path.join(self.root, "logs", "%s.jsonl" % incident_id))
        return self._events_cache[incident_id]

    def incident_ids(self) -> list:
        d = os.path.join(self.root, "alerts")
        return sorted(f[:-5] for f in os.listdir(d) if f.endswith(".json"))


def _matches(ev: dict, **f) -> bool:
    for key in ("principal_name", "event_name", "event_source", "aws_region",
                "source_ip", "source_asn"):
        want = f.get(key)
        if want and str(ev.get(key, "")).lower() != str(want).lower():
            return False
    if f.get("time_from") and ev["event_time"] < f["time_from"]:
        return False
    if f.get("time_to") and ev["event_time"] > f["time_to"]:
        return False
    if f.get("errors_only") and not ev.get("error_code"):
        return False
    if f.get("writes_only") and ev.get("read_only", True):
        return False
    text = f.get("contains")
    if text:
        blob = json.dumps([ev.get("request_parameters"), ev.get("resources"),
                           ev.get("response_elements"), ev.get("event_name")], default=str).lower()
        if text.lower() not in blob:
            return False
    return True


def _slim(ev: dict) -> dict:
    """The row shape the model sees in search results. Full record via get_events."""
    return {
        "event_id": ev["event_id"], "event_time": ev["event_time"],
        "event_name": ev["event_name"], "principal_name": ev["principal_name"],
        "aws_region": ev["aws_region"], "source_asn": ev["source_asn"],
        "error_code": ev.get("error_code"), "read_only": ev.get("read_only", True),
    }


def build_registry(store: IncidentStore, incident_id: str, run_state: dict) -> ToolRegistry:
    """Bind the tool plane to one incident. run_state collects the terminal verdict."""
    fetched: set = set()  # event_ids returned by get_events; the only ones submit_verdict accepts

    def search_logs(limit: int = 25, **filters):
        allowed = {"principal_name", "event_name", "event_source", "aws_region", "source_ip",
                   "source_asn", "time_from", "time_to", "errors_only", "writes_only", "contains"}
        unknown = set(filters) - allowed
        if unknown:
            raise ToolError("Unknown filter(s): %s. Allowed: %s"
                            % (", ".join(sorted(unknown)), ", ".join(sorted(allowed))),
                            kind="bad_arguments")
        events = store.events(incident_id)
        hits = [e for e in events if _matches(e, **filters)]
        limit = max(1, min(int(limit), 100))
        return {
            "total_matched": len(hits),
            "returned": min(len(hits), limit),
            "truncated": len(hits) > limit,
            "corpus_size": len(events),
            "events": [_slim(e) for e in hits[:limit]],
        }

    def get_events(event_ids: list):
        if not isinstance(event_ids, list) or not event_ids:
            raise ToolError("event_ids must be a non-empty list", kind="bad_arguments")
        if len(event_ids) > 20:
            raise ToolError("At most 20 event_ids per call (got %d)" % len(event_ids),
                            kind="bad_arguments")
        index = {e["event_id"]: e for e in store.events(incident_id)}
        missing = [i for i in event_ids if i not in index]
        if missing:
            raise ToolError("No such event_id(s): %s" % ", ".join(missing[:5]), kind="bad_arguments")
        fetched.update(event_ids)
        return {"events": [index[i] for i in event_ids]}

    def describe_principal(name: str):
        prof = store.principals.get(name)
        if not prof:
            raise ToolError(
                "No baseline for principal %r. Known principals: %s"
                % (name, ", ".join(sorted(store.principals))), kind="bad_arguments")
        return prof

    def submit_verdict(verdict: str, severity: str, recommended_action: str,
                       evidence_event_ids: list, rationale: str):
        errs = []
        if verdict not in VERDICTS:
            errs.append("verdict must be one of %s" % (VERDICTS,))
        if severity not in SEVERITIES:
            errs.append("severity must be one of %s" % (SEVERITIES,))
        if recommended_action not in ACTIONS:
            errs.append("recommended_action must be one of %s" % (ACTIONS,))
        if not isinstance(evidence_event_ids, list) or not evidence_event_ids:
            errs.append("evidence_event_ids must be a non-empty list of event_id strings")
        else:
            unfetched = [i for i in evidence_event_ids if i not in fetched]
            if unfetched:
                errs.append("evidence_event_ids not fetched with get_events (fetch them first): %s"
                            % ", ".join(map(str, unfetched[:5])))
        if not rationale or len(rationale) < 40:
            errs.append("rationale must be at least 40 characters")
        if errs:
            raise ToolError("; ".join(errs), kind="bad_arguments")
        run_state["verdict"] = {
            "verdict": verdict, "severity": severity,
            "recommended_action": recommended_action,
            "evidence_event_ids": evidence_event_ids, "rationale": rationale,
        }
        return {"accepted": True, "note": "Verdict recorded. Triage complete; stop now."}

    reg = ToolRegistry()
    reg.add(Tool(
        name="search_logs",
        description=(
            "Search this incident's audit log. All filters are AND-ed and exact-match except "
            "`contains`, which is a case-insensitive substring search over request parameters, "
            "resources and response elements. Returns slim rows plus `total_matched` — if "
            "`truncated` is true, narrow the filters rather than raising the limit. Start broad "
            "to learn the shape of the window, then narrow."),
        input_schema={
            "type": "object",
            "properties": {
                "principal_name": {"type": "string", "description": "Exact principal, e.g. alice.chen"},
                "event_name": {"type": "string", "description": "Exact API action, e.g. GetObject"},
                "event_source": {"type": "string", "description": "e.g. s3.amazonaws.com"},
                "aws_region": {"type": "string"},
                "source_ip": {"type": "string"},
                "source_asn": {"type": "string", "description": "e.g. 'AS14618 Amazon'"},
                "time_from": {"type": "string", "description": "ISO-8601 Z, inclusive lower bound"},
                "time_to": {"type": "string", "description": "ISO-8601 Z, inclusive upper bound"},
                "errors_only": {"type": "boolean", "description": "Only events with an error_code"},
                "writes_only": {"type": "boolean", "description": "Only mutating (non read-only) events"},
                "contains": {"type": "string", "description": "Substring over params/resources"},
                "limit": {"type": "integer", "description": "Max rows, 1-100. Default 25."},
            },
            "required": [],
        },
        fn=search_logs,
    ))
    reg.add(Tool(
        name="get_events",
        description=("Fetch complete records for up to 20 event_ids returned by search_logs. "
                     "Use this before citing an event as evidence — slim search rows omit "
                     "request parameters, resources and response elements."),
        input_schema={
            "type": "object",
            "properties": {"event_ids": {"type": "array", "items": {"type": "string"},
                                         "description": "1-20 event_id strings"}},
            "required": ["event_ids"],
        },
        fn=get_events,
    ))
    reg.add(Tool(
        name="describe_principal",
        description=(
            "Behavioural baseline for an IAM principal: home regions, typical API actions, "
            "typical active hours (UTC), known source ASNs, account age and scope notes. "
            "Activity is only anomalous relative to this baseline — a service role launching "
            "40 instances may be routine. Check the baseline before judging volume or timing."),
        input_schema={
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Principal name, e.g. svc-ci-deploy"}},
            "required": ["name"],
        },
        fn=describe_principal,
    ))
    reg.add(Tool(
        name="submit_verdict",
        description=(
            "Record the final triage verdict and end the investigation. Call exactly once, "
            "last. evidence_event_ids must cite the specific events that establish the verdict "
            "— for a false positive, the events that prove the activity was legitimate. "
            "Citing events you have not fetched with get_events is an error."),
        input_schema={
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": list(VERDICTS)},
                "severity": {"type": "string", "enum": list(SEVERITIES)},
                "recommended_action": {"type": "string", "enum": list(ACTIONS)},
                "evidence_event_ids": {"type": "array", "items": {"type": "string"}},
                "rationale": {"type": "string", "description": "Why, referencing the evidence. Min 40 chars."},
            },
            "required": ["verdict", "severity", "recommended_action", "evidence_event_ids", "rationale"],
        },
        fn=submit_verdict, is_terminal=True, mutates=True,
    ))
    return reg
