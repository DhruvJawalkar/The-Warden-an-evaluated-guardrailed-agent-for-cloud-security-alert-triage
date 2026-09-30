"""Behavioural tests beyond the week-1 contract: stops, budgets, pricing keys."""

from __future__ import annotations

from .test_loop_contract import make_loop
from warden.loop.agent_loop import ModelResponse, PRICING_USD_PER_MTOK, pricing_key
from warden.loop.transcript import ToolCall, Usage


def _calls(n, same=True):
    return [ModelResponse("s", [ToolCall("t%d" % i, "search_logs",
                                         {"limit": 1 if same else 1 + i})], "tool_use", Usage(1, 1))
            for i in range(n)]


def test_identical_calls_stall():
    loop, _ = make_loop(script=_calls(10))
    assert loop.run_until_done().stop_cause == "stalled_no_progress"


def test_varied_calls_hit_step_ceiling_not_stall():
    loop, _ = make_loop(script=_calls(10, same=False), max_steps=4)
    assert loop.run_until_done().stop_cause == "max_steps"


def test_consecutive_tool_errors_stop():
    script = [ModelResponse("s", [ToolCall("t%d" % i, "nope%d" % i, {})], "tool_use", Usage(1, 1))
              for i in range(10)]
    loop, _ = make_loop(script=script)
    assert loop.run_until_done().stop_cause == "stalled_tool_errors"


def test_context_budget_binds_when_compaction_cannot_help():
    loop, _ = make_loop(script=_calls(5, same=False))
    loop.budget.max_context_tokens = 5  # system prompt alone exceeds this
    run = loop.run_until_done()
    assert run.stop_cause == "max_context" and run.final_verdict is None


def test_pricing_keys_resolve_api_ids():
    for model in ("claude-haiku-4-5-20251001", "claude-sonnet-4-5-20250929",
                  "claude-sonnet-5-5", "claude-opus-5-5", "claude-fable-5-1"):
        assert pricing_key(model) in PRICING_USD_PER_MTOK, model


def test_prompt_v1_is_the_frozen_baseline_and_v2_extends_it():
    from warden.loop.agent_loop import V2_METHOD, build_system_prompt
    alert = {"account_id": "1", "alert_id": "A"}
    v1 = build_system_prompt(alert, ["search_logs"], "v1")
    v2 = build_system_prompt(alert, ["search_logs"], "v2")
    assert "METHOD" not in v1 and V2_METHOD in v2 and v2.endswith(v1.split("ALERT\n", 1)[1])
