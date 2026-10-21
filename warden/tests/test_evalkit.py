"""evalkit: metric arithmetic, label integrity for the new files, and run-record instrumentation.
No model and no MCP servers needed."""

from __future__ import annotations

import json
import math
import os

import pytest

from warden.evalkit import retrieval as R
from warden.evalkit import toolset as T
from warden.evalkit.stats import auroc, bootstrap_ci, paired_diff_ci
from warden.loop.transcript import StepRecord, ToolCall, ToolResult, returned_ids

RB = "datasets/runbooks_v1"


# --- retrieval metrics ---------------------------------------------------------------------

def test_dedupe_keeps_first_appearance_and_drops_titles():
    got = R.dedupe_sections([["A#x", "A#y"], ["A#x"], ["B#title"], ["B#z"]])
    assert got == ["A#x", "A#y", "B#z"]


def test_ndcg_rewards_rank_not_just_presence():
    gold = {"A#x"}
    assert R.ndcg_at_k(["A#x", "B#y", "C#z"], gold, 3) == 1.0
    assert R.ndcg_at_k(["B#y", "A#x", "C#z"], gold, 3) == pytest.approx(1 / math.log2(3))
    assert R.ndcg_at_k(["B#y", "C#z", "D#w"], gold, 3) == 0.0
    # recall cannot tell the first two apart; that is the point of reporting nDCG
    assert R.recall_at_k(["A#x", "B#y"], gold, 3) == R.recall_at_k(["B#y", "A#x"], gold, 3) == 1.0


def test_ndcg_two_gold_ideal_is_both_first():
    gold = {"A#x", "A#y"}
    assert R.ndcg_at_k(["A#x", "A#y"], gold, 3) == 1.0
    assert 0 < R.ndcg_at_k(["A#x", "B#z", "A#y"], gold, 3) < 1.0


def test_runbook_hit_is_softer_than_section_hit():
    ranked = ["A#other", "B#z"]
    assert R.recall_at_k(ranked, {"A#x"}, 3) == 0.0
    assert R.runbook_hit_at_k(ranked, {"A#x"}, 3) == 1.0
    assert R.runbook_hit_at_k(ranked, {"C#x"}, 3) == 0.0


def test_reciprocal_rank():
    assert R.reciprocal_rank(["B#a", "A#x"], {"A#x"}) == 0.5
    assert R.reciprocal_rank(["B#a"], {"A#x"}) == 0.0


def test_abstention_perfect_and_useless_signals():
    pos = [0.9, 0.8, 0.85, 0.95, 0.7, 0.75, 0.88, 0.92, 0.81, 0.79]
    assert R.abstention(pos, [0.1, 0.2, 0.3])["auroc"] == 1.0
    assert R.abstention(pos, [0.1, 0.2, 0.3])["false_accept_rate"] == 0.0
    same = R.abstention([0.5] * 10, [0.5] * 4)
    assert same["auroc"] == 0.5 and same["false_accept_rate"] == 1.0
    assert R.abstention(pos, []) == {}


def test_auroc_ties_count_half():
    assert auroc([1, 2], [1, 2]) == pytest.approx(0.5)


def test_bootstrap_is_seeded_and_brackets_the_mean():
    xs = [0, 1, 1, 0, 1, 1, 1, 0, 1, 1]
    assert bootstrap_ci(xs) == bootstrap_ci(xs)
    lo, hi = bootstrap_ci(xs)
    assert lo <= sum(xs) / len(xs) <= hi


def test_paired_diff_detects_a_consistent_gap_and_not_noise():
    a = [0.9, 0.8, 0.9, 0.85, 0.95, 0.9, 0.8, 0.9]
    b = [x - 0.2 for x in a]
    d, lo, hi = paired_diff_ci(a, b)
    assert d == pytest.approx(0.2) and lo > 0
    noise = paired_diff_ci([1, 0, 1, 0, 1, 0], [0, 1, 0, 1, 1, 0])
    assert noise[1] < 0 < noise[2]
    with pytest.raises(ValueError):
        paired_diff_ci([1], [1, 2])


# --- label integrity for the new files ---------------------------------------------------------

def test_negative_queries_are_labelled_empty_and_unique():
    qs = R.load_jsonl(os.path.join(RB, "queries_negative.jsonl"))
    assert len(qs) >= 10
    assert all(q["gold"] == [] for q in qs)
    assert len({q["qid"] for q in qs}) == len(qs)
    pos = {q["query"] for q in R.load_jsonl(os.path.join(RB, "queries.jsonl"))}
    assert not pos & {q["query"] for q in qs}


def test_incident_runbook_map_covers_every_scenario_with_real_runbooks():
    mapping = T.load_runbook_map("datasets/eval/incident_runbooks.json")
    key = T.load_key("datasets/v1")
    assert {r["scenario"] for r in key.values()} <= set(mapping)
    have = {f[:-3] for f in os.listdir(RB) if f.startswith("RB-") and f.endswith(".md")}
    for scenario, books in mapping.items():
        assert books and set(books) <= have, scenario
        assert not any(b.startswith("RB-GEN") for b in books), "GEN runbooks apply to all; do not list"


# --- run-record instrumentation ---------------------------------------------------------------

def test_returned_ids_reads_records_and_section_lists():
    assert returned_ids({"events": [{"event_id": "e1"}, {"event_id": "e2"}]})["event_ids"] == ["e1", "e2"]
    assert returned_ids({"results": [{"section_id": "A#x"}]})["section_ids"] == ["A#x"]
    assert returned_ids({"section_id": "A#x", "text": "t"})["section_ids"] == ["A#x"]
    assert returned_ids("a string error") == {"event_ids": [], "section_ids": []}


def test_step_record_json_carries_rendered_chars_and_ids_but_not_for_errors():
    ok = ToolResult("c1", "get_events", {"events": [{"event_id": "e1"}]}, rendered_chars=123)
    bad = ToolResult("c2", "search_logs", "boom", is_error=True, error_kind="bad_arguments", rendered_chars=9)
    j = StepRecord(index=0, text="", tool_calls=[ToolCall("c1", "get_events", {}), ToolCall("c2", "search_logs", {})],
                   tool_results=[ok, bad]).to_json()
    a, b = j["tool_results"]
    assert a["rendered_chars"] == 123 and a["event_ids"] == ["e1"]
    assert b["rendered_chars"] == 9 and "event_ids" not in b


# --- toolset metrics on synthetic runs ----------------------------------------------------------

def _run(inc, calls, cited):
    """calls: [(name, args, result_extra)] -> a run dict shaped like RunRecord.to_json()."""
    steps = [{"tool_calls": [{"id": "c%d" % i, "name": n, "arguments": a}],
              "tool_results": [dict({"call_id": "c%d" % i, "name": n, "is_error": False, "latency_ms": 5}, **x)]}
             for i, (n, a, x) in enumerate(calls)]
    return {"incident_id": inc, "steps": steps, "final_verdict": {"verdict": "true_positive", "evidence_event_ids": cited}}


KEY = {"I1": {"scenario": "s", "ground_truth": {"verdict": "true_positive",
                                                 "required_evidence_event_ids": ["e1", "e2", "e3", "e4"]}}}


def test_funnel_separates_search_selection_and_reasoning_failures():
    run = _run("I1", [
        ("search_logs", {}, {"event_ids": ["e1", "e2", "e3"], "rendered_chars": 500}),
        ("get_events", {"event_ids": ["e1", "e2"]}, {"event_ids": ["e1", "e2"], "rendered_chars": 300}),
    ], cited=["e1"])
    f = T.evidence_funnel([run], KEY)
    assert f["stages"] == {"cited": 1, "fetched_not_cited": 1, "surfaced_not_fetched": 1, "never_surfaced": 1}


def test_funnel_degrades_honestly_on_runs_without_ids():
    run = _run("I1", [("get_events", {"event_ids": ["e1", "e2"]}, {})], cited=["e1"])
    f = T.evidence_funnel([run], KEY)
    assert f["runs_with_ids"] == 0
    assert "never_surfaced" not in f["stages"] and f["stages"]["not_fetched (surfacing unknown)"] == 2


def test_per_tool_counts_errors_and_leaves_chars_na_when_unrecorded():
    run = _run("I1", [("search_logs", {}, {"rendered_chars": 400}),
                      ("search_logs", {}, {"is_error": True, "error_kind": "bad_arguments"}),
                      ("get_events", {"event_ids": ["e1"]}, {})], cited=["e1"])
    t = T.per_tool([run])
    assert t["search_logs"]["calls"] == 2 and t["search_logs"]["error_rate"] == 0.5
    assert t["search_logs"]["error_kinds"] == {"bad_arguments": 1}
    assert t["search_logs"]["chars_n"] == 1 and t["get_events"]["mean_chars"] is None


def test_runbook_use_needs_the_expected_runbook():
    run = _run("I1", [("search_runbooks", {}, {"section_ids": ["RB-A#x"]}),
                      ("get_runbook_section", {"section_id": "RB-A#x"}, {})], cited=[])
    u = T.runbook_use([run], KEY, {"s": ["RB-A"]})
    assert (u["searched"], u["read"], u["consulted"], u["surfaced"]) == (1, 1, 1, 1)
    u = T.runbook_use([run], KEY, {"s": ["RB-B"]})
    assert (u["consulted"], u["surfaced"]) == (0, 0)


def test_lint_flags_thin_descriptions_and_undocumented_params():
    good = {"name": "a", "description": "x" * 80,
            "input_schema": {"properties": {"q": {"description": "d"}}, "required": ["q"]}}
    bad = {"name": "b", "description": "short",
           "input_schema": {"properties": {"q": {"type": "string"}}, "required": []}}
    lint = T.lint_schemas([good, bad])
    assert lint["tools"][1]["undocumented_params"] == ["q"]
    assert len(lint["findings"]) == 2 and all(f.startswith("b:") for f in lint["findings"])
    assert T.lint_schemas([good, dict(good)])["findings"] == ["duplicate tool name: a"]


def test_loop_run_records_rendered_chars_and_event_ids_end_to_end():
    from warden.loop.agent_loop import AgentLoop, Budget, ModelResponse, ScriptedClient
    from warden.loop.tools import IncidentStore, build_registry
    from warden.loop.transcript import RunRecord, Transcript, Usage
    state: dict = {}
    reg = build_registry(IncidentStore("datasets/v1"), "WRD-0001", state)
    tr = Transcript("system")
    tr.add_user("go")
    script = [ModelResponse("s", [ToolCall("t1", "search_logs", {"limit": 3})], "tool_use", Usage(1, 1)),
              ModelResponse("s", [ToolCall("t2", "nope", {})], "tool_use", Usage(1, 1)),
              ModelResponse("done", [], "end_turn", Usage(1, 1))]
    run = AgentLoop(ScriptedClient(script), reg, tr, Budget(max_steps=5), RunRecord.new("WRD-0001", "scripted"),
                    state).run_until_done()
    results = [r for s in run.to_json()["steps"] for r in s["tool_results"]]
    ok, err = results[0], results[1]
    assert ok["rendered_chars"] > 0 and len(ok["event_ids"]) == 3
    assert err["is_error"] and err["rendered_chars"] > 0 and "event_ids" not in err


@pytest.mark.parametrize("strategy", ["fixed", "heading"])
def test_section_ranking_matches_what_the_server_returns(strategy, monkeypatch):
    """The retrieval metrics are only meaningful if they grade the ranking search_runbooks returns."""
    pytest.importorskip("rank_bm25")
    pytest.importorskip("fastmcp")
    from warden.toolplane import runbook_rag
    monkeypatch.setenv("WARDEN_RAG_STRATEGY", strategy)
    monkeypatch.setenv("WARDEN_RAG_RETRIEVER", "bm25")
    monkeypatch.setenv("WARDEN_RUNBOOKS", RB)
    monkeypatch.setattr(runbook_rag, "_cache", {})
    res = R.evaluate(RB, strategies=(strategy,), retrievers=("bm25",))
    rows = res["results"]["%s+bm25" % strategy]["rows"]
    queries = {q["qid"]: q["query"] for q in R.load_jsonl(os.path.join(RB, "queries.jsonl"))}
    for row in rows[:12]:
        served = [r["section_id"] for r in runbook_rag.search_runbooks_impl(queries[row["qid"]], 5)["results"]]
        assert served == row["top5"], row["qid"]
