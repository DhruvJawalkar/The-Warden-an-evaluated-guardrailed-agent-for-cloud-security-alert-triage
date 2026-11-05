"""Summarising compaction (opt-in) next to the default elision: pairing, ids, flag, idempotence."""

from __future__ import annotations

import os
import re

import pytest

from warden.loop.agent_loop import (
    COMPACTION_MODES, SUMMARY_HEAD, AgentLoop, Budget, ModelResponse, ScriptedClient,
)
from warden.loop.tools import IncidentStore, build_registry
from warden.loop.transcript import RunRecord, ToolCall, Transcript, Usage

ROOT = os.environ.get("WARDEN_DATASET", "datasets/v1")
SEARCH = ("search_logs: total_matched=140 returned=25 truncated=true corpus_size=600\n"
          "event_id | event_time | event_name | principal | region | asn | error | write\n"
          + "\n".join("evt-WRD-0001-%04d | 2026-08-24T04:%02d:00Z | AssumeRole | alice.chen | us-east-1"
                      " | AS14618 Amazon | - | n" % (i, i % 60) for i in range(1, 21)))
FETCH = ('get_events: 2 record(s)\n{"event_id":"evt-WRD-0001-0007","principal_name":"svc-deploy"}\n'
         '{"event_id":"evt-WRD-0001-0013","principal_name":"alice.chen"}')


def make(mode, pairs=14, big=3000, max_ctx=3000):
    store, state = IncidentStore(ROOT), {}
    reg = build_registry(store, "WRD-0001", state)
    tr = Transcript("system")
    tr.add_user("Triage alert ALT-0001.")
    run = RunRecord.new("WRD-0001", "scripted")
    loop = AgentLoop(ScriptedClient([]), reg, tr, Budget(max_context_tokens=max_ctx), run, state,
                     compaction=mode)
    for i in range(pairs):
        if i == 3:
            name, args, out = "get_events", {"event_ids": ["evt-WRD-0001-0007", "evt-WRD-0001-0013"]}, FETCH
        elif i == 5:
            name, args, out = "describe_principal", {"name": "alice.chen"}, '{"home_region":"us-east-1"}'
        else:
            name, args, out = "search_logs", {"principal_name": "p%d" % i}, SEARCH
        tr.add_assistant_blocks([{"type": "text", "text": "step %d: checking" % i},
                                 {"type": "tool_use", "id": "t%d" % i, "name": name, "input": args}])
        tr.add_tool_results([("t%d" % i, out + " " * big, False)])
    return loop


def pairing(loop):
    uses, results = [], []
    for m in loop.transcript.messages:
        for b in m["content"]:
            if b.get("type") == "tool_use":
                uses.append(b["id"])
            elif b.get("type") == "tool_result":
                results.append(b["tool_use_id"])
    return uses, results


def alternates(loop):
    roles = [m["role"] for m in loop.transcript.messages]
    return roles[0] == "user" and all(a != b for a, b in zip(roles, roles[1:]))


def summary_text(loop):
    blocks = [b["text"] for b in loop.transcript.messages[0]["content"]
              if b.get("type") == "text" and b["text"].startswith(SUMMARY_HEAD)]
    assert len(blocks) <= 1, "summary block duplicated"
    return blocks[0] if blocks else ""


def test_default_is_the_week1_elision_and_flag_is_validated():
    assert COMPACTION_MODES == ("elide", "summarise")
    loop = make("elide")
    assert loop.compaction == "elide" and loop.run.compaction == "elide"
    assert loop.maybe_compact()
    text = " ".join(b.get("content", "") for m in loop.transcript.messages for b in m["content"]
                    if b.get("type") == "tool_result")
    assert "[elided to save context" in text and summary_text(loop) == ""
    with pytest.raises(ValueError):
        make("magic")


@pytest.mark.parametrize("mode", COMPACTION_MODES)
def test_pairing_and_alternation_survive_in_both_modes(mode):
    loop = make(mode)
    assert loop.maybe_compact()
    uses, results = pairing(loop)
    assert sorted(uses) == sorted(results), "orphaned tool_use/tool_result"
    assert alternates(loop)
    assert loop.transcript.messages[0]["content"][0]["text"] == "Triage alert ALT-0001."


def test_summarise_replaces_old_turns_and_fits():
    loop = make("summarise")
    before = len(loop.transcript.messages)
    assert loop.maybe_compact()
    assert len(loop.transcript.messages) < before
    assert loop.transcript.estimated_tokens() <= int(3000 * loop.COMPACT_AT)
    text = summary_text(loop)
    assert "Event ids below are verbatim" in text and "re-run a call" in text
    assert "elided" not in str(loop.transcript.messages[1:3])


def test_fetched_event_ids_survive_verbatim_and_are_marked_citable():
    loop = make("summarise")
    loop.maybe_compact()
    text = summary_text(loop)
    tail = " ".join(str(m) for m in loop.transcript.messages[1:])
    for eid in ("evt-WRD-0001-0007", "evt-WRD-0001-0013"):
        assert eid in text or eid in tail
    line = [ln for ln in text.splitlines() if ln.startswith("Event ids you fetched")]
    assert line and "evt-WRD-0001-0007" in line[0] and "evt-WRD-0001-0013" in line[0]
    assert "svc-deploy" in text  # principals seen in the dropped fetch


def test_summary_records_queries_counts_and_baseline_excerpt():
    loop = make("summarise")
    loop.maybe_compact()
    text = summary_text(loop)
    assert re.search(r'search_logs \{"principal_name":"p\d+"\}: 25 of 140 matched.*alice.chen', text) \
        or re.search(r"search_logs .*: 20 of 140|returned", text) or "of 140 matched" in text
    assert "describe_principal" in text and "home_region" in text
    assert "(+16 more, re-run to list)" in text  # 20 ids seen, 4 listed
    assert "| note: step 0: checking" in text
    lines = [ln for ln in text.splitlines() if ln.startswith("- ")]
    assert [int(re.search(r"note: step (\d+)", ln).group(1)) for ln in lines] == sorted(
        int(re.search(r"note: step (\d+)", ln).group(1)) for ln in lines), "summary is not chronological"


def test_second_compaction_merges_into_one_block_and_loses_no_ids():
    loop = make("summarise", pairs=14, max_ctx=3000)
    loop.maybe_compact()
    first = summary_text(loop)
    n1 = len(loop.run_dropped)
    for i in range(100, 112):  # more traffic, then compact again
        loop.transcript.add_assistant_blocks(
            [{"type": "tool_use", "id": "t%d" % i, "name": "search_logs", "input": {"limit": i}}])
        loop.transcript.add_tool_results([("t%d" % i, SEARCH + " " * 3000, False)])
    assert loop.maybe_compact()
    second = summary_text(loop)  # asserts a single block
    assert len(loop.run_dropped) > n1 and second.startswith(SUMMARY_HEAD)
    assert first.splitlines()[1] in second  # earlier lines are kept
    assert "evt-WRD-0001-0007" in second
    uses, results = pairing(loop)
    assert sorted(uses) == sorted(results) and alternates(loop)


def test_error_results_are_summarised_not_hidden():
    loop = make("summarise", pairs=2, big=0)
    loop.transcript.add_assistant_blocks([{"type": "tool_use", "id": "te", "name": "search_logs",
                                           "input": {"bogus": 1}}])
    loop.transcript.add_tool_results([("te", "Unknown argument(s) for search_logs: bogus", True)])
    for i in range(20, 30):
        loop.transcript.add_assistant_blocks([{"type": "tool_use", "id": "t%d" % i,
                                               "name": "search_logs", "input": {"limit": i}}])
        loop.transcript.add_tool_results([("t%d" % i, "x" * 3000, False)])
    loop.maybe_compact()
    assert "ERROR Unknown argument" in summary_text(loop)


def test_below_threshold_nothing_changes():
    loop = make("summarise", pairs=2, big=0, max_ctx=120_000)
    snap = loop.transcript.snapshot()
    assert loop.maybe_compact() is False and loop.transcript.snapshot() == snap


def test_a_short_conversation_still_compacts_safely():
    """Too few messages to cut much. The newest result alone (20k chars) exceeds the limit and no
    compaction can shrink it; that case belongs to Budget.exceeded ("max_context"), as with elision."""
    loop = make("summarise", pairs=2, big=20000, max_ctx=3000)
    before = loop.transcript.estimated_tokens()
    assert loop.maybe_compact()
    uses, results = pairing(loop)
    assert sorted(uses) == sorted(results) and alternates(loop)
    assert loop.transcript.estimated_tokens() < before


def test_a_full_run_with_summarise_still_submits_a_verdict():
    """End to end through run_until_done: compaction triggers mid-run, the later submit still works."""
    store, state = IncidentStore(ROOT), {}
    reg = build_registry(store, "WRD-0001", state)
    seed = "evt-WRD-0001-0001"

    def r(i, tool, **a):
        return ModelResponse("note %d" % i, [ToolCall("c%d" % i, tool, a)], "tool_use", Usage(1, 1))
    script = [r(i, "search_logs", limit=30 - i) for i in range(1, 7)]
    script += [r(7, "describe_principal", name="alice.chen"), r(8, "get_events", event_ids=[seed]),
               r(9, "submit_verdict", verdict="true_positive", severity="high",
                 recommended_action="escalate", evidence_event_ids=[seed],
                 rationale="Console login without MFA from a new ASN. " * 2)]
    tr = Transcript("system " * 200)
    tr.add_user("Triage alert ALT-0001.")
    run = RunRecord.new("WRD-0001", "scripted")
    loop = AgentLoop(ScriptedClient(script), reg, tr, Budget(max_context_tokens=2500), run, state,
                     compaction="summarise")
    out = loop.run_until_done()
    assert out.stop_cause == "verdict_submitted" and out.final_verdict["evidence_event_ids"] == [seed]
    assert any(s.compacted for s in out.steps)
    assert out.to_json()["compaction"] == "summarise"
    uses, results = pairing(loop)
    assert sorted(uses) == sorted(results)
