# Week 3 notes: durable orchestration (LangGraph)

## 0. Version freeze (2026-10-24)

Installed with `pip install -e ".[graph]"` equivalents into the existing venv (Python 3.14.7); `pip check` clean.

| package | version | role |
|---|---|---|
| langgraph | 1.2.17 | graph runtime |
| langgraph-checkpoint | 4.3.0 | checkpointer interface (transitive) |
| langgraph-checkpoint-postgres | 3.2.0 | `PostgresSaver` |
| langgraph-prebuilt | 1.1.1 | transitive |
| langgraph-sdk | 0.4.9 | transitive |
| langchain-core | 1.7.0 | transitive (langgraph depends on it; we do not use chains) |
| langchain-protocol | 0.0.20 | transitive |
| langsmith | 0.14.12 | transitive; tracing is not enabled |
| psycopg / psycopg-binary | 3.3.6 | Postgres driver |
| psycopg-pool | 3.3.3 | connection pool |
| orjson / ormsgpack | 3.13.0 / 1.13.0 | transitive, serialisation |
| Postgres (Docker) | `postgres:17.6` | `docker-compose.yml`, host port 5433 |

Direct pins are in `pyproject.toml` under the `graph` extra. Release notes are read on Fridays only.

DSN: `postgresql://warden:warden@localhost:5433/warden` (dev-only credentials, bound to 127.0.0.1).
`docker compose up -d --wait postgres`. Smoke test: `PostgresSaver.setup()` created its tables and returned.

## Decisions taken at kickoff

- Model and prompt unchanged from week 2: Haiku 4.5, prompt v2, so the comparison stays one variable at a time.
- Per-run spend cap: $0.50 (`Budget.max_usd` default already matches). Ask before raising it.
- Enrich sub-agent is in scope. Nothing is being cut.
- Context compaction gets upgraded from elision to summarisation (work item 5).

- Verifier is hybrid: deterministic checks first; then an injection guardrail; then at most one LLM
  verification call per incident, only if confidence is still low.
- Compaction upgrade is behind a flag, default off.
- One eval run per experiment (cost).

## Verifier: deterministic layer (built)

`graph/verify.py` is a pure function of (alert, verdict, observations). It never reads the answer key
or dataset files (a test asserts this), so it can be unit tested offline and log text is only compared
against ids and names, never interpreted. Checks: cited events returned in full by `get_events`;
verdict vs action not contradictory; `describe_principal` for the alerting and every cited principal;
a `search_logs(contains=<resource>)` for every resource in the cited events; any other principal that
pivot search surfaces must be described.

Note: `submit_verdict` already rejects ids not in `fetched`, so check 1 is a redundant second line
that also covers the graph path; the resource pivot and unexamined-principal checks are the new
behaviour (the WRD-0019 / WRD-0017 fix). 90 tests pass (11 new). Not yet measured on the LLM: whether
it moves WRD-0019 / WRD-0017 is a week-3 result, not a claim.

## Skeleton graph (built 2026-11-05)

`graph/nodes.py` + `graph/build.py`: `plan -> investigate -> verify -> (investigate | report)`, thread id =
incident id. 98 tests pass (8 new, `tests/test_graph.py`, offline: ScriptedClient + in-process registry +
MemorySaver).

- **plan** is deterministic (four generic questions from the alert, no model call). It does add a
  "Questions to answer" block to the user message, so it is a prompt change versus week 2. Keep that in mind
  when comparing against the week-2 MCP arm: it is a second variable alongside the graph itself.
- **investigate** builds a fresh `AgentLoop`, registry and transcript per attempt and discards them. The
  checkpoint holds only observations, verdict, gaps and spend. A retry gets the gap instructions and the
  previous verdict in its first message and is told to re-fetch cited events (a fresh registry's `fetched`
  set is empty). A retry that submits nothing keeps the earlier proposed verdict.
- **Spend cap** is per incident across attempts: each attempt gets `max_usd - cost so far`.
- **verify** runs the deterministic checks. Retry ceiling 1 (`attempts <= 1` routes back).
- **report** has three statuses: `verified`, `unverified` (checks still failing after the retry),
  `unresolved` (no verdict). It only *proposes* a ticket for contain/escalate. No code path in the graph calls
  `create_ticket`; the interrupt gate (item 4) will be the only one.
- Not built yet: the regex injection guardrail and the single LLM verify call, the Postgres saver, the gate,
  summarisation compaction, the enrich sub-graph. Not run against the real model.

## Decisions (2026-11-05)

- Injection guardrail for the LLM verify pass is **regex/heuristic** for now. A classifier is a later
  option; week 5 (adversarial suite) is where its miss rate gets measured.
- Verify retry ceiling is **1**: a failed deterministic check routes back to investigate once.
  Revisit only if the 20-incident run shows recall left on the table.

## Open items

- Exact guardrail patterns (what counts as instruction-like text in log fields).
