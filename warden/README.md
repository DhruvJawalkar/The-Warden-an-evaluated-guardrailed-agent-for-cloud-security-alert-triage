# Warden

An evaluated, guardrailed agent for cloud-security alert triage.

Warden takes a SIEM alert, investigates it across audit logs and principal
baselines, and returns a triage verdict with cited evidence. The interesting
part is not the agent — it is the harness around it: a versioned golden
dataset, three-layer evaluation, per-step cost attribution, and an adversarial
suite for indirect prompt injection through attacker-controlled log content.

**Status: week 1 of 6.** Hand-written ReAct loop and dataset v1.

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
  loop/tools.py        week-1 tool plane; becomes FastMCP servers in week 2
  loop/transcript.py   message state, step and run records
  evalkit/             empty until week 4
datasets/v1/           generated; committed so results are reproducible
docs/                  work items and design notes
```

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
