"""Deterministic verifier: does the investigation support the proposed verdict?

A pure function of (alert, verdict, observations). It never reads the answer key, the dataset
files or the network, so it is testable offline and cannot be steered by log content: the log
text is only ever compared against ids and names, never interpreted.

Each failed check yields a Gap whose `instruction` is what the investigate node is told on retry.
The LLM pass (verify_llm) runs only if these checks pass but confidence is still low.
"""

from __future__ import annotations

import re
from typing import Iterable

from warden.graph.state import Gap

# request_parameters keys that name a resource worth pivoting on ("who else touched this?").
RESOURCE_KEYS = ("secretId", "bucketName", "functionName", "volumeId", "snapshotId",
                 "userName", "groupName", "roleArn", "role")

CONTAINING_ACTIONS = ("contain", "escalate")


def _fetched_events(observations: Iterable[dict]) -> dict:
    out = {}
    for o in observations:
        if o["tool"] == "get_events" and not o["is_error"] and o.get("payload"):
            for e in o["payload"].get("events", []):
                out[e["event_id"]] = e
    return out


def _described(observations: Iterable[dict]) -> set:
    return {o["arguments"].get("name") for o in observations
            if o["tool"] == "describe_principal" and not o["is_error"]}


def _search_terms(observations: Iterable[dict]) -> list:
    return [str(o["arguments"]["contains"]).lower() for o in observations
            if o["tool"] == "search_logs" and not o["is_error"] and o["arguments"].get("contains")]


def _resource_values(event: dict) -> list:
    params = event.get("request_parameters") or {}
    vals = []
    for k in RESOURCE_KEYS:
        v = params.get(k)
        if isinstance(v, str) and v:
            # an ARN is searched by its last segment: that is what appears elsewhere in the log
            vals.append(re.split(r"[/:]", v)[-1] if v.startswith("arn:") else v)
    return vals


def _pivot_hit_principals(observations: Iterable[dict], term: str) -> set:
    names = set()
    for o in observations:
        if (o["tool"] == "search_logs" and not o["is_error"] and o.get("payload")
                and str(o["arguments"].get("contains", "")).lower() == term):
            names.update(e["principal_name"] for e in o["payload"].get("events", []))
    return names


def verify(alert: dict, verdict: dict, observations: list) -> list:
    """Return the list of Gaps; an empty list means every deterministic check passed."""
    gaps: list = []
    fetched = _fetched_events(observations)
    cited = list(verdict.get("evidence_event_ids") or [])

    # 1. every cited event was actually returned in full by get_events (not merely asserted)
    missing = [i for i in cited if i not in fetched]
    if missing:
        gaps.append(Gap(
            check="cited_events_observed",
            detail="cited but never returned by get_events: %s" % ", ".join(missing[:5]),
            instruction="Fetch these events with get_events or stop citing them: %s"
                        % ", ".join(missing[:5])))

    # 2. verdict and recommended action do not contradict each other
    v, act = verdict.get("verdict"), verdict.get("recommended_action")
    if v == "true_positive" and act == "close_benign":
        gaps.append(Gap(
            check="verdict_action_consistent",
            detail="true_positive verdict with recommended_action close_benign",
            instruction="Your verdict says malicious but your action closes it as benign. "
                        "Reconcile them, and say which is wrong."))
    if v == "false_positive" and act in CONTAINING_ACTIONS:
        gaps.append(Gap(
            check="verdict_action_consistent",
            detail="false_positive verdict with recommended_action %s" % act,
            instruction="Your verdict says benign but your action is %s. Reconcile them, "
                        "and say which is wrong." % act))

    # 3. the baseline was checked for the alerting principal and for every cited actor
    actors = {alert.get("primary_principal")} | {fetched[i]["principal_name"]
                                                 for i in cited if i in fetched}
    actors.discard(None)
    unchecked = sorted(actors - _described(observations))
    if unchecked:
        gaps.append(Gap(
            check="baseline_checked",
            detail="no describe_principal for: %s" % ", ".join(unchecked),
            instruction="Call describe_principal for %s before judging their activity."
                        % ", ".join(unchecked)))

    # 4. resource pivot: for each resource in the cited events, search who else touched it,
    #    and baseline any other principal that turns up
    terms = _search_terms(observations)
    described = _described(observations)
    pivoted, new_principals = set(), {}
    for i in cited:
        for val in _resource_values(fetched.get(i, {})):
            low = val.lower()
            if low in pivoted:
                continue
            pivoted.add(low)
            if not any(low in t for t in terms):
                gaps.append(Gap(
                    check="resource_pivot",
                    detail="no search_logs(contains=%r) for a resource in the cited events" % val,
                    instruction="Search who else touched %r with search_logs(contains=%r), "
                                "then reconsider whether the alerting principal is the cause."
                                % (val, val)))
            else:
                for name in _pivot_hit_principals(observations, low) - described - actors:
                    new_principals.setdefault(name, val)
    for name, val in sorted(new_principals.items()):
        gaps.append(Gap(
            check="unexamined_principal",
            detail="%s touched %r but was never described" % (name, val),
            instruction="%s also touched %r. Call describe_principal for them and fetch "
                        "their events before closing." % (name, val)))
    return gaps
