"""Offline demo: watch compaction and each stop cause fire, using ScriptedClient.

    python scripts/demo_loop.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from warden.loop.agent_loop import AgentLoop, Budget, ModelResponse, ScriptedClient  # noqa: E402
from warden.loop.tools import IncidentStore, build_registry  # noqa: E402
from warden.loop.transcript import RunRecord, ToolCall, Transcript, Usage  # noqa: E402

ROOT = os.environ.get("WARDEN_DATASET", "datasets/v1")


def call(i, name, **args):
    return ModelResponse("step %d" % i, [ToolCall("t%d" % i, name, args)], "tool_use", Usage(10, 10))


def run(title, script, **budget):
    store = IncidentStore(ROOT)
    state: dict = {}
    reg = build_registry(store, "WRD-0001", state)
    tr = Transcript("system")
    tr.add_user("go")
    loop = AgentLoop(ScriptedClient(script), reg, tr, Budget(**budget),
                     RunRecord.new("WRD-0001", "scripted"), state)
    r = loop.run_until_done()
    print("\n== %s\n   stop_cause=%s steps=%d compacted_steps=%s"
          % (title, r.stop_cause, len(r.steps), [s.index for s in r.steps if s.compacted]))
    return loop


# 1. same call three times -> stalled_no_progress
run("identical call x3", [call(i, "search_logs", limit=1) for i in range(10)])

# 2. A,B,A,B,A,B -> stalled_no_progress
run("alternating A/B", [call(i, "search_logs", limit=1 + i % 2) for i in range(10)])

# 3. unknown tool over and over -> stalled_tool_errors (args vary so repeat rule doesn't fire first)
loop = run("5 consecutive tool errors",
           [call(i, "no_such_tool_%d" % i) for i in range(10)])
print("   last model-visible error:", loop.transcript.messages[-1]["content"][0]["content"][:200])

# 4. varied broad searches, tiny context -> compaction fires and pairing survives
loop = run("compaction", [call(i, "search_logs", limit=100, aws_region="r%d" % i) if i % 2
                          else call(i, "search_logs", limit=100) for i in range(8)],
           max_context_tokens=3000, max_steps=8)
tail = [b for m in loop.transcript.messages for b in m["content"] if b.get("type") == "tool_result"]
print("   sample elided result:", next((b["content"] for b in tail
                                       if b["content"].startswith("[elided")), "none")[:220])

# 5. step ceiling, no stall pattern
run("max_steps", [call(i, "search_logs", limit=1 + i) for i in range(10)], max_steps=4)

# 6. a verdict ends the run
ok = ModelResponse("done", [ToolCall("v", "submit_verdict", dict(
    verdict="true_positive", severity="high", recommended_action="escalate",
    evidence_event_ids=["evt-WRD-0001-0001"], rationale="x" * 50))], "tool_use", Usage(5, 5))
fetch = ModelResponse("fetch", [ToolCall("f", "get_events", {"event_ids": ["evt-WRD-0001-0001"]})],
                      "tool_use", Usage(5, 5))
run("verdict submitted", [fetch, ok])
