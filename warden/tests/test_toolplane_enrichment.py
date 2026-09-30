"""Week-2 servers beyond the ported three: threat intel, asset graph, ticket writer, and the policy
seam (toolsets + fail-closed write gate) that decides which of them a model may use."""

from __future__ import annotations

import json
import os
import pathlib

import pytest

pytest.importorskip("fastmcp")

from warden.data import enrichment  # noqa: E402
from warden.loop.tools import ToolError  # noqa: E402
from warden.toolplane.asset_graph import describe_asset_impl, describe_trust_impl  # noqa: E402
from warden.toolplane.client import McpRegistry, is_read_only  # noqa: E402
from warden.toolplane.threat_intel import lookup_asn_impl  # noqa: E402

ROOT = os.environ.get("WARDEN_DATASET", "datasets/v1")
ENR = os.environ.get("WARDEN_ENRICHMENT", "datasets/enrichment_v1")


@pytest.fixture(autouse=True)
def _enrichment_env(monkeypatch):
    monkeypatch.setenv("WARDEN_ENRICHMENT", ENR)


# --- data ------------------------------------------------------------------------

def test_generator_is_deterministic_and_matches_committed_files():
    a = enrichment.build_threat_intel(20260930)
    assert a == enrichment.build_threat_intel(20260930)
    committed = json.loads(pathlib.Path(ENR, "threat_intel.json").read_text(encoding="utf-8"))
    assert committed == json.loads(json.dumps(a))


def test_generator_never_touches_ground_truth():
    src = pathlib.Path(enrichment.__file__).read_text(encoding="utf-8")
    for forbidden in ("ground_truth", "incidents.jsonl", "required_evidence", "verdict"):
        assert forbidden not in src, "enrichment must not be derived from the answer key"


def test_feed_is_noisy_not_an_answer_key():
    entries = json.loads(pathlib.Path(ENR, "threat_intel.json").read_text(encoding="utf-8"))["entries"]
    assert entries["AS14618"]["abuse_reports_90d"] > 100  # a routine source carries reports
    assert "AS204957" not in entries and "AS51396" not in entries  # unknown networks exist


# --- impls -----------------------------------------------------------------------

def test_lookup_asn_accepts_every_form_and_reports_absence_honestly():
    for form in ("AS49505", "49505", "AS49505 Selectel", " as49505 "):
        assert lookup_asn_impl(form)["asn"] == "AS49505"
    miss = lookup_asn_impl("AS204957 Alviva")
    assert miss["found"] is False and "not evidence" in miss["note"]
    with pytest.raises(ToolError) as e:
        lookup_asn_impl("nonsense")
    assert e.value.kind == "bad_arguments"


def test_describe_asset_accepts_names_and_arns():
    a = describe_asset_impl("acme-customer-exports")
    assert describe_asset_impl("arn:aws:s3:::acme-customer-exports/some/key")["resource"] == a["resource"]
    assert describe_asset_impl("s3://acme-customer-exports/x")["owner_team"] == "Customer Data Platform"
    secret = describe_asset_impl("arn:aws:secretsmanager:us-east-1:418209773165:secret:prod/db/master")
    assert secret["type"] == "secret"
    assert describe_asset_impl("dropzone-9f2a-public")["owner_team"] is None
    with pytest.raises(ToolError):
        describe_asset_impl("no-such-bucket")
    assert "bob.martins" in describe_trust_impl("svc-ci-deploy")["assumable_by"]


# --- toolsets and the write gate --------------------------------------------------

@pytest.fixture(scope="module")
def w1():
    reg = McpRegistry("WRD-0001", {}, dataset=ROOT, toolset="w1").start()
    yield reg
    reg.close()


@pytest.fixture(scope="module")
def full(tmp_path_factory):
    os.environ["WARDEN_TICKET_DIR"] = str(tmp_path_factory.mktemp("tickets"))
    os.environ["WARDEN_ENRICHMENT"] = ENR
    os.environ["WARDEN_RAG_RETRIEVER"] = "bm25"  # keep torch out of the fast suite
    reg = McpRegistry("WRD-0001", {}, dataset=ROOT, toolset="full").start()
    yield reg
    reg.close()
    os.environ.pop("WARDEN_TICKET_DIR", None)
    os.environ.pop("WARDEN_RAG_RETRIEVER", None)


def test_w1_toolset_is_exactly_the_week1_surface(w1):
    assert w1.names() == ["describe_principal", "get_events", "search_logs", "submit_verdict"]


def test_full_toolset_adds_tools_but_keeps_the_originals(full, w1):
    assert set(w1.names()) < set(full.names())
    assert {"lookup_asn", "describe_asset", "describe_trust", "create_ticket",
            "search_runbooks", "get_runbook_section"} <= set(full.names())
    by_name = {s["name"]: s for s in full.schemas()}
    assert all(by_name[s["name"]] == s for s in w1.schemas() if s["name"] != "submit_verdict")


def test_every_remote_tool_declares_readonly_or_is_gated(full):
    for name, (_, _, tool) in full._remote.items():
        assert getattr(tool, "annotations", None) is not None, "%s declares no annotations" % name
        assert is_read_only(tool) == (name != "create_ticket"), name


def test_unannotated_tool_is_treated_as_a_write():
    class Bare:
        annotations = None
    assert is_read_only(Bare()) is False


TICKET = {"title": "Possible key compromise", "severity": "high", "recommended_action": "escalate",
          "body": "See events.", "evidence_event_ids": ["evt-WRD-0001-0001"]}


def test_write_tool_is_denied_without_approval(full):
    full.approver = None
    with pytest.raises(ToolError) as e:
        full.dispatch("create_ticket", dict(TICKET))
    assert e.value.kind == "approval_required"
    assert not list(pathlib.Path(os.environ["WARDEN_TICKET_DIR"]).glob("*.json")), "denied call wrote"


def test_denied_approver_blocks_and_granted_approver_writes_idempotently(full):
    seen = []
    full.approver = lambda name, args: seen.append((name, args["title"])) or False
    with pytest.raises(ToolError):
        full.dispatch("create_ticket", dict(TICKET))
    assert seen == [("create_ticket", TICKET["title"])]

    full.approver = lambda name, args: True
    first, _ = full.dispatch("create_ticket", dict(TICKET))
    again, _ = full.dispatch("create_ticket", dict(TICKET))  # a retry must not double-file
    assert first == again and first["status"] == "open"
    files = list(pathlib.Path(os.environ["WARDEN_TICKET_DIR"]).glob("*.json"))
    assert len(files) == 1 and json.loads(files[0].read_text())["incident_id"] == "WRD-0001"
    full.approver = None


def test_model_cannot_name_the_incident_on_a_write(full):
    full.approver = lambda name, args: True
    with pytest.raises(ToolError) as e:
        full.dispatch("create_ticket", dict(TICKET, incident_id="WRD-0002"))
    assert e.value.kind == "bad_arguments"
    full.approver = None


def test_runbook_search_over_the_wire_and_section_roundtrip(full):
    res, _ = full.dispatch("search_runbooks", {"query": "is a burst of instance launches from a build role normal?", "top_k": 3})
    assert len(res["results"]) == 3 and res["strategy"] == "heading"
    assert all(r["section_id"] and r["snippet"] for r in res["results"])
    sec, _ = full.dispatch("get_runbook_section", {"section_id": res["results"][0]["section_id"]})
    assert sec["text"] and sec["section_id"] == res["results"][0]["section_id"]
    for bad in ({"query": "  "}, {"query": "x", "top_k": "many"}):
        with pytest.raises(ToolError) as e:
            full.dispatch("search_runbooks", bad)
        assert e.value.kind == "bad_arguments"
    with pytest.raises(ToolError):
        full.dispatch("get_runbook_section", {"section_id": "RB-NOPE#x"})


def test_new_read_tools_over_the_wire(full):
    assert full.dispatch("lookup_asn", {"asn": "AS49505 Selectel"})[0]["reputation"] == "poor"
    assert full.dispatch("describe_asset", {"resource": "acme-customer-exports"})[0]["owner_team"]
    with pytest.raises(ToolError) as e:
        full.dispatch("describe_asset", {"resource": "nope"})
    assert e.value.kind == "bad_arguments"
