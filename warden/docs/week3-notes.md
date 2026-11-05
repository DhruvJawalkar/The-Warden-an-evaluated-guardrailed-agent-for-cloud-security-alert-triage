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

DSN: `postgresql://warden:warden@127.0.0.1:5433/warden` (dev-only credentials, bound to 127.0.0.1).
Use the literal `127.0.0.1`, not `localhost`: on this Windows host `localhost` made psycopg wait out the whole
20 s connect timeout before falling back (measured), and every connection pays it.
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

## Postgres checkpointer and the kill test (2026-11-05)

`PostgresSaver` (sync; the async saver needs the selector event loop policy on Windows, so it is avoided).
`scripts/graph_killtest_worker.py` runs the graph in its own process with a slow scripted model and appends every
model call, tool call and verify entry to a ledger file; `tests/test_graph_resume.py` kills it with
`Popen.kill()` (TerminateProcess, same as `taskkill /F`), restarts it on the same thread id, and compares the
ledger with the final state. No API calls. 101 tests pass with Postgres up; the 3 resume tests skip without it.

| kill point | what ran after restart | state after | real calls wasted |
|---|---|---|---|
| between nodes (inside verify) | resumed at `verify`; investigate NOT re-run | 3 observations, 1 verify attempt, cost = 3 calls | 0 |
| inside investigate (after 2 model calls) | resumed at `investigate`; node replayed from its start | 3 observations, no duplicates, cost = 3 calls | 2 model calls + 1 read-only tool call |
| thread already finished | nothing re-run | report returned from the checkpoint | 0 |

A manual `taskkill /F /PID` run showed the same ledger: `start,model,tool:describe_principal,model | resume:investigate,
model,tool:describe_principal,model,tool:get_events,model,tool:submit_verdict | verify_enter`.

**What this does and does not prove.** A node is the unit of atomicity. State never doubles up and the checkpointed
spend never counts the killed attempt, but a kill mid-investigate loses that attempt's work: the real API spend for
the killed calls is gone from `cost_usd` (it is real money, just unrecorded) and its read-only tool calls run twice.
The loss is bounded by one investigate attempt (about $0.04 at week-2 rates). The write tool is not exposed to this
risk: `create_ticket` runs only behind the gate (outside investigate) and is idempotent. If "no duplicated tool
calls or double spend" must hold mid-investigate too, the investigate loop would need to checkpoint per step
(a sub-graph with one model turn per superstep); that is a design choice, not done here.

## Interrupt gate (2026-11-05)

Replaces the client-side approver callback. `report -> gate -> file_ticket`; `gate.py` holds the pure parts
(`proposal_for`, `gate_payload`, `decide`), `nodes.py` the two nodes. 145 tests, all passing with Postgres up.

- **Two nodes on purpose.** LangGraph re-runs an interrupted node from its top on resume, so `gate` does only
  `interrupt()` plus parsing (no side effects) and records the decision in checkpointed state. `file_ticket` is
  the only caller of `create_ticket`. It opens the client's new one-tool `ticket` toolset (never offered to the
  model) with an approver that accepts *exactly* the approved arguments; the client's read-only/approval policy
  is still the enforcement point, and a tampered payload is refused (tested).
- **Resume value:** `{"action": "approve"}`, `{"action": "reject", "reason"}`, or
  `{"action": "edit", "edits": {title|severity|recommended_action|body}}`, each with an optional `reviewer`.
  Evidence ids and incident id are not editable.
- **Fails closed.** `decide()` never raises and never defaults to approve. Non-dict, unknown action, extra
  fields, an `approve` carrying a ticket, edits to non-editable fields, or any invalid edited value (the whole
  reply, not just that field) become a recorded reject. 23 malformed shapes are tested. No timeout path
  exists. Compiled without a checkpointer the run returns at the gate with `pending_decision` and the interrupt payload; it cannot be resumed and nothing is written (tested).
- **No reply is not a decision.** On langgraph 1.2.17, `Command(resume={})` re-pauses and
  `Command(resume=None)` raises `UnboundLocalError` inside the library. Both leave the gate open, write nothing,
  and a later valid reply works. Pinned by a test so an upgrade that changes it is noticed.
- **Budget exhaustion is now a human decision.** A run with no verdict (max_steps, max_usd, stall, ...) proposes
  an `UNRESOLVED:` escalation ticket built from the alert alone (severity from `severity_reported`, evidence = the
  alert's seed events, body states it is not an agent finding) and pauses at the gate. If the alert has no seed
  events there is nothing `create_ticket` could file, so the run just ends unresolved.
- **Only contain/escalate verdicts reach the gate.** `close_benign` and `monitor` write nothing and do not
  pause. A closed-benign verdict is therefore not human-reviewed; that is a policy choice to revisit in week 5.
- **Durable across processes (Postgres):** a run pauses at the gate and its process exits; a different process
  supplies the decision and the ticket is filed once with investigate not re-run; replaying the approval on the
  finished thread writes nothing more.
- **Crash between the write and its checkpoint:** `file_ticket` re-runs. The decision was checkpointed before it
  ran, so the re-run files the same title, and the ticket id is a hash of (incident, title): it overwrites the
  same outbox file rather than adding a second one (idempotency from week 2).
- With toolset `full` the model still sees `create_ticket` and any call is denied by the default approver
  (fail closed); the graph does not use `full`.

## Batch policy, thread ids and TTL (2026-11-05, decided with the user)

`graph/batch.py` (`python -m warden.graph.batch run | pending | decide | purge`), `graph/threads.py`.

- **Gate policy in a batch.** Held threads stay paused for a human: `--hold ID,ID` and `--hold-first N` (default 1:
  the first N incidents to reach the gate with a proposed ticket). Every other gate is auto-rejected with
  `reviewer="eval-harness"`, so no ticket is filed and the wait is not in the run's latency (`seconds_excl_gate_wait`
  stops at the gate). Unresolved runs are auto-rejected unless named in `--hold`. The held cases are the manual
  approve/edit path: `pending` shows the proposed ticket, `decide --action approve|reject|edit` resumes it.
- **Re-running is safe.** A finished thread is never re-run (spend protection); a thread found paused stays paused
  (never auto-rejected) unless `--auto-reject-pending`.
- **Closed-benign / monitor verdicts still bypass the gate**, as agreed; revisit in week 5.
- **Thread id = `<experiment>:<incident>`**, validated (`[A-Za-z0-9._-]`, no `:`). A new experiment name starts
  clean; the same name resumes. Tested: two experiments on one saver do not share observations.
- **TTL 6 h.** langgraph-checkpoint-postgres 3.2.0 has no TTL, so `purge_stale` removes threads whose newest
  checkpoint (`checkpoint->>'ts'`) is older than the TTL, via the saver's own `delete_thread` (checkpoints, blobs and
  writes). It runs at the start of every batch `run`, and as `batch purge [--experiment E] [--ttl-hours H]`. Tested
  against Postgres at 5h50 (kept) and 6h05 (removed), with the experiment filter treated literally. A held gate older
  than 6 h is purged too; decide within the window or re-run the experiment under a new name.
- The `run` subcommand itself (real model) has not been executed; only the policy logic is tested, offline.

## Decisions (2026-11-05)

- Injection guardrail for the LLM verify pass is **regex/heuristic** for now. A classifier is a later
  option; week 5 (adversarial suite) is where its miss rate gets measured.
- Verify retry ceiling is **1**: a failed deterministic check routes back to investigate once.
  Revisit only if the 20-incident run shows recall left on the table.

## Open items

- Exact guardrail patterns (what counts as instruction-like text in log fields).
