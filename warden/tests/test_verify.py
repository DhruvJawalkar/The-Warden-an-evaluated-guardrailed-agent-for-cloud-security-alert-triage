"""Deterministic verifier: each check fails on its own and the clean case passes."""

from __future__ import annotations

import inspect

from warden.graph import verify as verify_mod
from warden.graph.state import WardenState
from warden.graph.verify import verify
from warden.loop.tools import IncidentStore, describe_principal_impl, get_events_impl, search_logs_impl

ALERT = {"primary_principal": "svc-a"}


def ev(eid, who="svc-a", **params):
    return {"event_id": eid, "principal_name": who, "request_parameters": params}


def get(*events):
    return {"tool": "get_events", "arguments": {}, "is_error": False, "payload": {"events": list(events)}}


def describe(name):
    return {"tool": "describe_principal", "arguments": {"name": name}, "is_error": False, "payload": {}}


def search(term, *hits):
    return {"tool": "search_logs", "arguments": {"contains": term}, "is_error": False,
            "payload": {"events": [{"event_id": "x", "principal_name": h} for h in hits]}}


def verdict(**kw):
    base = {"verdict": "true_positive", "recommended_action": "escalate",
            "evidence_event_ids": ["e1"], "rationale": "r" * 50}
    return {**base, **kw}


def checks(gaps):
    return sorted(g["check"] for g in gaps)


def test_clean_investigation_passes():
    obs = [get(ev("e1", secretId="prod/db/master")), describe("svc-a"), search("prod/db/master", "svc-a")]
    assert verify(ALERT, verdict(), obs) == []


def test_cited_event_never_fetched():
    obs = [get(ev("e2")), describe("svc-a")]
    assert "cited_events_observed" in checks(verify(ALERT, verdict(), obs))


def test_errored_get_events_does_not_count():
    obs = [{"tool": "get_events", "arguments": {}, "is_error": True, "payload": None}, describe("svc-a")]
    assert "cited_events_observed" in checks(verify(ALERT, verdict(), obs))


def test_verdict_action_contradiction():
    obs = [get(ev("e1")), describe("svc-a")]
    assert "verdict_action_consistent" in checks(
        verify(ALERT, verdict(recommended_action="close_benign"), obs))
    assert "verdict_action_consistent" in checks(
        verify(ALERT, verdict(verdict="false_positive", recommended_action="contain"), obs))
    assert verify(ALERT, verdict(verdict="false_positive", recommended_action="close_benign"), obs) == []


def test_baseline_required_for_alerting_and_cited_actor():
    obs = [get(ev("e1", who="svc-b"))]
    gaps = verify(ALERT, verdict(), obs)
    assert checks(gaps) == ["baseline_checked"]
    assert "svc-a" in gaps[0]["detail"] and "svc-b" in gaps[0]["detail"]


def test_resource_pivot_required_and_arn_uses_last_segment():
    obs = [get(ev("e1", role="arn:aws:iam::1:role/analytics-readall")), describe("svc-a")]
    gaps = verify(ALERT, verdict(), obs)
    assert checks(gaps) == ["resource_pivot"] and "analytics-readall" in gaps[0]["detail"]
    obs.append(search("analytics-readall", "svc-a"))
    assert verify(ALERT, verdict(), obs) == []


def test_pivot_surfaces_unexamined_principal():
    obs = [get(ev("e1", functionName="invoice-renderer")), describe("svc-a"),
           search("invoice-renderer", "svc-a", "svc-ci-deploy")]
    gaps = verify(ALERT, verdict(), obs)
    assert checks(gaps) == ["unexamined_principal"] and "svc-ci-deploy" in gaps[0]["detail"]
    obs.append(describe("svc-ci-deploy"))
    assert verify(ALERT, verdict(), obs) == []


def test_every_gap_has_an_instruction():
    obs = [get(ev("e2", who="svc-b", secretId="s"))]
    gaps = verify(ALERT, verdict(recommended_action="close_benign"), obs)
    assert gaps and all(g["instruction"] and g["detail"] for g in gaps)


def test_verifier_is_pure():
    src = inspect.getsource(verify_mod)
    for banned in ("answer_key", "AnswerKey", "datasets", "open(", "anthropic", "requests"):
        assert banned not in src


def test_real_dataset_chain_wrd_0019():
    """Replay the root-cause pivot on real data: alerting principal's secret read, then the
    resource search that exposes the deploy principal."""
    store = IncidentStore("datasets/v1")
    iid = "WRD-0019"
    alert = store.alert(iid)
    hits = search_logs_impl(store, iid, contains="prod/db/master")
    seed = alert["seed_event_ids"]
    obs = [
        {"tool": "get_events", "arguments": {}, "is_error": False,
         "payload": get_events_impl(store, iid, seed)},
        {"tool": "describe_principal", "arguments": {"name": alert["primary_principal"]},
         "is_error": False, "payload": describe_principal_impl(store, alert["primary_principal"])},
    ]
    v = verdict(evidence_event_ids=seed)
    assert "resource_pivot" in checks(verify(alert, v, obs))          # never searched the secret
    obs.append({"tool": "search_logs", "arguments": {"contains": "prod/db/master"},
                "is_error": False, "payload": hits})
    others = {e["principal_name"] for e in hits["events"]} - {alert["primary_principal"]}
    gaps = verify(alert, v, obs)
    assert {g["detail"].split()[0] for g in gaps if g["check"] == "unexamined_principal"} == others


def test_state_schema_declares_reducers():
    hints = WardenState.__annotations__
    assert {"observations", "verify_attempts", "llm_verify_calls", "cost_usd"} <= set(hints)
