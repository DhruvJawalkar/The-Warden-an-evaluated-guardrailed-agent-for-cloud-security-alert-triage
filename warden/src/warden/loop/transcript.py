"""Message state and run records.

The Transcript is the agent's working memory. RunRecord is what week 4 grades:
every step, every tool call, every token, every dollar. Emit it even on crashes
— a run that failed is data, and an eval harness that only sees successes is
measuring the wrong population.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class ToolResult:
    call_id: str
    name: str
    payload: Any  # native Python; rendering to text is the loop's job
    is_error: bool = False
    latency_ms: int = 0
    error_kind: Optional[str] = None  # unknown_tool | bad_arguments | tool_failed


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0

    def add(self, other: "Usage") -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens


@dataclass
class StepRecord:
    index: int
    text: str
    tool_calls: list = field(default_factory=list)
    tool_results: list = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    cost_usd: float = 0.0
    latency_ms: int = 0
    stop_reason: str = ""
    compacted: bool = False

    def to_json(self) -> dict:
        return {
            "index": self.index,
            "text": self.text,
            "tool_calls": [asdict(c) for c in self.tool_calls],
            "tool_results": [
                {"call_id": r.call_id, "name": r.name, "is_error": r.is_error,
                 "error_kind": r.error_kind, "latency_ms": r.latency_ms,
                 "payload_preview": json.dumps(r.payload, default=str)[:400]}
                for r in self.tool_results
            ],
            "usage": asdict(self.usage),
            "cost_usd": round(self.cost_usd, 6),
            "latency_ms": self.latency_ms,
            "stop_reason": self.stop_reason,
            "compacted": self.compacted,
        }


@dataclass
class RunRecord:
    """One triage attempt. This is the unit of evaluation."""

    run_id: str
    incident_id: str
    model: str
    started_at: float
    steps: list = field(default_factory=list)
    final_verdict: Optional[dict] = None
    stop_cause: str = ""
    finished_at: float = 0.0
    prompt_version: str = ""

    @classmethod
    def new(cls, incident_id: str, model: str) -> "RunRecord":
        return cls(run_id=uuid.uuid4().hex[:12], incident_id=incident_id,
                   model=model, started_at=time.time())

    @property
    def total_usage(self) -> Usage:
        u = Usage()
        for s in self.steps:
            u.add(s.usage)
        return u

    @property
    def total_cost_usd(self) -> float:
        return sum(s.cost_usd for s in self.steps)

    def tool_call_names(self) -> list:
        return [c.name for s in self.steps for c in s.tool_calls]

    def to_json(self) -> dict:
        u = self.total_usage
        return {
            "run_id": self.run_id,
            "incident_id": self.incident_id,
            "model": self.model,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "wall_clock_s": round((self.finished_at or time.time()) - self.started_at, 2),
            "step_count": len(self.steps),
            "stop_cause": self.stop_cause,
            "prompt_version": self.prompt_version,
            "final_verdict": self.final_verdict,
            "totals": {"usage": asdict(u), "cost_usd": round(self.total_cost_usd, 6)},
            "trajectory": self.tool_call_names(),
            "steps": [s.to_json() for s in self.steps],
        }

    def save(self, run_dir: str = "runs") -> str:
        os.makedirs(run_dir, exist_ok=True)
        path = os.path.join(run_dir, "%s-%s.json" % (self.incident_id, self.run_id))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_json(), fh, indent=2, default=str)
        return path


class Transcript:
    """Provider-shaped message list plus the hooks the loop needs.

    Deliberately dumb: it stores and reports. Every policy decision about what
    to keep, drop or summarise lives in AgentLoop, where it is visible.
    """

    def __init__(self, system: str):
        self.system = system
        self.messages: list = []

    def add_user(self, text: str) -> None:
        self.messages.append({"role": "user", "content": [{"type": "text", "text": text}]})

    def add_assistant_blocks(self, blocks: list) -> None:
        self.messages.append({"role": "assistant", "content": blocks})

    def add_tool_results(self, rendered: list) -> None:
        """rendered: list of (call_id, text, is_error)."""
        content = [
            {"type": "tool_result", "tool_use_id": cid, "content": text, "is_error": is_err}
            for cid, text, is_err in rendered
        ]
        self.messages.append({"role": "user", "content": content})

    def estimated_tokens(self) -> int:
        """Cheap proxy: ~4 chars per token. Good enough for a compaction trigger,
        useless for billing — use the API's reported usage for cost."""
        return (len(self.system) + len(json.dumps(self.messages, default=str))) // 4

    def snapshot(self) -> list:
        return json.loads(json.dumps(self.messages, default=str))
