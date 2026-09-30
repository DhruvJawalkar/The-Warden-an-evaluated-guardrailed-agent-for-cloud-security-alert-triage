"""Dataset integrity. These must pass before any eval work in week 4.

An answer key with a dangling event_id silently makes an incident ungradeable,
and you would not notice until your success rate looked mysteriously low.
"""

from __future__ import annotations

import json
import os

import pytest

from warden.data.schema import ACTIONS, SEVERITIES, TIERS, VERDICTS, read_jsonl

ROOT = os.environ.get("WARDEN_DATASET", "datasets/v1")


@pytest.fixture(scope="module")
def incidents():
    return read_jsonl(os.path.join(ROOT, "incidents.jsonl"))


def test_manifest_matches_incidents(incidents):
    with open(os.path.join(ROOT, "manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    assert manifest["incident_count"] == len(incidents) == 20
    assert sum(manifest["tier_distribution"].values()) == 20


def test_controlled_vocabularies(incidents):
    for inc in incidents:
        gt = inc["ground_truth"]
        assert gt["verdict"] in VERDICTS
        assert gt["severity"] in SEVERITIES
        assert gt["recommended_action"] in ACTIONS
        assert inc["tier"] in TIERS


def test_every_referenced_event_exists(incidents):
    """The core integrity check: no dangling ids in the answer key."""
    for inc in incidents:
        events = {e["event_id"] for e in read_jsonl(os.path.join(ROOT, inc["log_path"]))}
        gt = inc["ground_truth"]
        for field in ("required_evidence_event_ids", "distractor_event_ids"):
            missing = set(gt[field]) - events
            assert not missing, "%s: %s references missing %s" % (inc["incident_id"], field, missing)
        missing_seed = set(inc["alert"]["seed_event_ids"]) - events
        assert not missing_seed, "%s: alert seed ids missing" % inc["incident_id"]


def test_evidence_and_distractors_are_disjoint(incidents):
    for inc in incidents:
        gt = inc["ground_truth"]
        overlap = set(gt["required_evidence_event_ids"]) & set(gt["distractor_event_ids"])
        assert not overlap, "%s: %s is both evidence and distractor" % (inc["incident_id"], overlap)


def test_every_incident_has_evidence_and_rationale(incidents):
    for inc in incidents:
        gt = inc["ground_truth"]
        assert gt["required_evidence_event_ids"], "%s has no evidence" % inc["incident_id"]
        assert len(gt["rationale"]) > 80, "%s rationale too thin" % inc["incident_id"]
        assert "submit_verdict" in gt["required_tool_calls"]


def test_benign_incidents_require_corroboration(incidents):
    """No false positive may be closable from search_logs alone.

    Closing a benign-looking alert on event names is exactly the behaviour the
    noisy tier exists to punish. Every FP must force the agent to corroborate:
    usually describe_principal (the baseline), occasionally get_events (reading
    a policy body rather than matching its event name).
    """
    for inc in incidents:
        if inc["ground_truth"]["verdict"] == "false_positive":
            required = set(inc["ground_truth"]["required_tool_calls"])
            assert required & {"describe_principal", "get_events"}, (
                "%s is benign but closable from search_logs alone" % inc["incident_id"])


def test_hard_tier_spans_multiple_hops(incidents):
    hard = [i for i in incidents if i["tier"] == "hard"]
    assert len(hard) == 4
    for inc in hard:
        gt = inc["ground_truth"]
        assert len(gt["required_evidence_event_ids"]) >= 3, "%s too shallow" % inc["incident_id"]
        assert gt["min_steps"] >= 5, "%s min_steps too low for hard tier" % inc["incident_id"]


def test_alerts_leak_no_ground_truth():
    """The agent's entry point must not contain the answer."""
    forbidden = {"verdict", "ground_truth", "mitre_techniques", "rationale",
                 "required_evidence_event_ids", "recommended_action"}
    for name in os.listdir(os.path.join(ROOT, "alerts")):
        with open(os.path.join(ROOT, "alerts", name), encoding="utf-8") as fh:
            alert = json.load(fh)
        assert not (forbidden & set(alert)), "%s leaks ground truth" % name


def test_signal_is_a_minority_of_each_log(incidents):
    """If the signal is most of the window, search is trivial and so is the eval."""
    for inc in incidents:
        ratio = inc["signal_event_count"] / inc["event_count"]
        assert ratio < 0.10, "%s: signal is %.1f%% of the window" % (inc["incident_id"], ratio * 100)
