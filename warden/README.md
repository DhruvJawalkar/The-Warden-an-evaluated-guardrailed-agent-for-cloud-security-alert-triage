# Warden

An evaluated, guardrailed agent for cloud-security alert triage.

Warden takes a SIEM alert, investigates it across audit logs and principal
baselines, and returns a triage verdict with cited evidence. The interesting
part is not the agent — it is the harness around it: a versioned golden
dataset, three-layer evaluation, per-step cost attribution, and an adversarial
suite for indirect prompt injection through attacker-controlled log content.

**Status: week 2 of 6.** Hand-written ReAct loop, dataset v1, and the tool plane as FastMCP servers.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env          # add ANTHROPIC_API_KEY

make gen                      # regenerate datasets/v1 (deterministic)
make test                     # dataset integrity + loop contract tests
python -m warden.loop.agent_loop --check          # what is still stubbed
python -m warden.loop.agent_loop --incident WRD-0001
```

## Dataset v1

20 incidents, 7,190 events, seed `20260903`. Regenerating with the same seed
produces byte-identical logs and alerts.

| tier | n | what it tests |
|---|---|---|
| easy | 9 | malicious, contiguous signal, single principal |
| noisy | 7 | benign but attack-shaped — only the principal's baseline separates them |
| hard | 4 | malicious, multi-hop across days, sessions or principals |

Verdicts: 13 true positive, 7 false positive. Signal is under 10% of every
window, so search cannot be brute-forced.

Ground truth is structured, not prose — `verdict`, `severity`,
`recommended_action` and `required_evidence_event_ids` are all machine-checkable,
so week 4 scores task success against the agent's **end state** rather than the
wording of its final message. `distractor_event_ids` records the
plausible-but-wrong evidence a sloppy run cites instead.

The agent only ever sees `alerts/`, `logs/` and `principals.json`.
`incidents.jsonl` is the answer key and must never enter the tool plane.

### Known limitation in v1

Severity is close to collinear with verdict: every false positive resolves to
`informational` or `low`, and most true positives to `high` or `critical`. An
agent can score well on severity by inferring it from the verdict, so in week 4
do not report severity accuracy as an independent metric — or widen the benign
tier with a genuine medium-severity policy violation that still closes benign.

## Layout

```
src/warden/
  data/schema.py       Event / Alert / Incident / GroundTruth / PrincipalProfile
  data/scenarios.py    the 20 incident builders
  data/generator.py    deterministic generator
  loop/agent_loop.py   the ReAct loop (5 stubs open — see docs/week1-workitems.md)
  loop/tools.py        tool implementations + the in-process registry (kept as the test oracle)
  loop/transcript.py   message state, step and run records
  toolplane/           week 2: five FastMCP servers over stdio, plus the client the loop uses
    log_search.py        search_logs, get_events          (ported from week 1, byte-identical schemas)
    asset_graph.py       describe_principal; describe_asset, describe_trust
    threat_intel.py      lookup_asn
    runbook_rag.py       search_runbooks, get_runbook_section, runbook:// resources, a prompt
    ticket_writer.py     create_ticket                    (the only write tool; approval-gated)
    client.py            McpRegistry: same surface as ToolRegistry, so AgentLoop is unchanged
  rag/                 corpus, chunkers (fixed / heading), retrievers (bm25 / dense / hybrid), recall@k
  data/enrichment.py   deterministic generator for the threat-intel and asset tables
  evalkit/             empty until week 4
datasets/v1/           generated; committed so results are reproducible (the tagged week-1 baseline)
datasets/enrichment_v1/  threat intel + asset inventory; separate from v1 on purpose
datasets/runbooks_v1/  16 runbooks + 48 labelled queries for the recall@k measurement
docs/                  work items and design notes
```

## Tool plane (week 2)

Run any server on its own, or point the MCP Inspector at it:

```bash
python -m warden.toolplane.log_search            # stdio

# MCP Inspector. Use the config file: the Inspector swallows a bare `python -m ...` (it parses -m itself).
# `python` must resolve to the venv, and WARDEN_DATASET must be set for log-search / asset-graph.
export WARDEN_DATASET="$PWD/datasets/v1"
npx @modelcontextprotocol/inspector --config mcp.inspector.json --server log-search          # UI
npx @modelcontextprotocol/inspector --cli --config mcp.inspector.json --server threat-intel \
    --method tools/call --tool-name lookup_asn --tool-arg 'asn=AS49505 Selectel'             # CLI

python -m warden.loop.agent_loop --incident WRD-0001                  # --tools mcp --toolset w1 (default)
python -m warden.loop.agent_loop --incident WRD-0001 --tools inproc   # the week-1 path
python -m warden.loop.agent_loop --incident WRD-0001 --toolset full   # adds the week-2 tools
```

Design points worth knowing:

- **Stateless servers.** Every call carries its own ids; nothing is remembered between calls. The
  only per-process state is a read-only cache.
- **`incident_id` is bound by the client**, injected on every call and hidden from the schema the
  model sees, so a poisoned log line cannot steer the model into reading another incident.
- **`submit_verdict` stays client-side.** It is loop control, and it needs the set of event ids the
  client has seen returned by `get_events`.
- **Toolsets are policy.** `w1` is exactly the week-1 tool surface, so moving to MCP changes one
  variable. `full` adds the week-2 tools and is an experiment of its own.
- **Writes fail closed.** A tool that does not declare `readOnlyHint=true` cannot run without an
  approver; the default approver denies. Week 3 turns that callback into a LangGraph interrupt.
- **Parity is tested, not assumed.** `tests/test_toolplane.py` sends the same calls through the
  in-process registry and the MCP servers for all 20 incidents and asserts identical payloads and
  identical model-facing schemas.

## Roadmap

| week | milestone |
|---|---|
| 1 | hand-written loop, dataset v1 |
| 2 | tool plane as FastMCP servers; runbook RAG with measured recall@k |
| 3 | LangGraph: durable checkpointing, verifier node, human-in-the-loop gate |
| 4 | eval harness, OTel GenAI tracing, CI regression gate |
| 5 | guardrails, adversarial injection suite, attack success rate |
| 6 | ablation study and eval report |

## Notes

Version freeze: 2026-09-30 at `w1-baseline`. `anthropic==1.9.0` (Python 3.14.7); baseline model `claude-haiku-4-5-20251001`. Do not bump the SDK until the week-6 comparison is done.

Week-2 freeze, same date: `fastmcp==4.0.10` (pulls `mcp==2.2.0`, which implements the 2026-07-28 spec),
`rank-bm25==0.2.2`, `sentence-transformers==6.1.0`. RAG dependencies live in the `rag` extra so the loop
and its tests never need torch: `pip install -e ".[rag]"`.
