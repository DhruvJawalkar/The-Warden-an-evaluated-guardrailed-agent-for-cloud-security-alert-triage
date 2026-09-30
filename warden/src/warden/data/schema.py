"""Dataset schema for Warden.

Everything the agent reads and everything the evaluator grades against is
defined here. Two rules govern this file:

1. Ground truth is *structured*, never prose. `verdict`, `recommended_action`
   and `required_evidence_event_ids` are all machine-checkable, so week 4 can
   score task success against the agent's END STATE rather than against the
   wording of its final message.
2. Anything the agent is allowed to see lives on Event/Alert. Anything it must
   not see lives on GroundTruth. Keep that boundary clean or your eval leaks.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

SCHEMA_VERSION = "1.0.0"

# --- controlled vocabularies -------------------------------------------------
VERDICTS = ("true_positive", "false_positive")
SEVERITIES = ("critical", "high", "medium", "low", "informational")
TIERS = ("easy", "noisy", "hard")
ACTIONS = ("escalate", "contain", "close_benign", "monitor")


@dataclass
class Event:
    """One CloudTrail-shaped audit record. Flattened for readability."""

    event_id: str
    event_time: str  # ISO-8601 Z
    event_source: str  # e.g. s3.amazonaws.com
    event_name: str  # e.g. GetObject
    aws_region: str
    source_ip: str
    source_asn: str
    user_agent: str
    principal_id: str
    principal_type: str  # IAMUser | AssumedRole | AWSService | Root
    principal_name: str
    account_id: str
    session_id: Optional[str] = None
    request_parameters: dict = field(default_factory=dict)
    response_elements: Optional[dict] = None
    error_code: Optional[str] = None
    resources: list = field(default_factory=list)
    read_only: bool = True

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class Alert:
    """What the SIEM fired. This is the agent's entry point."""

    alert_id: str
    incident_id: str
    detected_at: str
    rule_id: str
    rule_name: str
    severity_reported: str
    summary: str
    primary_principal: str
    account_id: str
    region: str
    seed_event_ids: list = field(default_factory=list)

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class GroundTruth:
    """Never shown to the agent. The evaluator's answer key.

    `required_evidence_event_ids` is the heart of it: a verdict without the
    supporting events is a lucky guess, and week 4 must be able to tell the
    difference. `distractor_event_ids` are the plausible-but-wrong events that
    a sloppy agent will cite instead.
    """

    verdict: str
    severity: str
    recommended_action: str
    scenario: str
    tier: str
    mitre_techniques: list = field(default_factory=list)
    required_evidence_event_ids: list = field(default_factory=list)
    distractor_event_ids: list = field(default_factory=list)
    required_tool_calls: list = field(default_factory=list)
    principals_involved: list = field(default_factory=list)
    resources_involved: list = field(default_factory=list)
    min_steps: int = 3
    max_reasonable_steps: int = 12
    rationale: str = ""

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class Incident:
    incident_id: str
    tier: str
    scenario: str
    alert: Alert
    ground_truth: GroundTruth
    log_path: str
    event_count: int
    signal_event_count: int
    generated_at: str
    generator_version: str
    seed: int

    def to_json(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class PrincipalProfile:
    """Behavioural baseline. Exposed to the agent via describe_principal().

    This is what makes the benign-but-noisy tier solvable: an agent that never
    checks the baseline cannot distinguish a CI role legitimately launching 40
    instances from an attacker mining crypto. It is also what makes those
    incidents *hard* — the information exists but must be sought.
    """

    principal_id: str
    name: str
    principal_type: str
    is_service: bool
    department: str
    created_days_ago: int
    home_regions: list = field(default_factory=list)
    typical_events: list = field(default_factory=list)
    typical_hours_utc: list = field(default_factory=list)  # [start, end]
    known_asns: list = field(default_factory=list)
    notes: str = ""

    def to_json(self) -> dict:
        return asdict(self)


def write_jsonl(path, rows) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, separators=(",", ":"), sort_keys=False) + "\n")


def read_jsonl(path) -> list:
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
