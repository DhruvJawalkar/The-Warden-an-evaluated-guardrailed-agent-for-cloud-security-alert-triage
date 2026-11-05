# Week 2 — work items (retrospective completion record)

> Written on 2026-11-05, after the fact. The original week-2 plan was not kept in the repo, so the
> items below are reconstructed from the README roadmap ("tool plane as FastMCP servers; runbook RAG
> with measured recall@k"), `docs/week2-notes.md`, and commit `6632e78` (2026-09-30). Each ticked item
> points at evidence that exists in the repo. Nothing here is a claim beyond what those sources show.

Goal: move the tool plane out of process as FastMCP servers without changing model-facing behaviour,
add a runbook RAG with measured retrieval quality, and re-baseline the agent on the new plane.

Ship criteria:

- [x] Five FastMCP servers (log-search, asset-graph, threat-intel, runbook-rag, ticket-writer) — `src/warden/toolplane/`
- [x] `AgentLoop` runs unchanged over stdio via `McpRegistry` — `toolplane/client.py`, `tests/test_toolplane.py`
- [x] Parity with the in-process registry proven, not assumed: identical model-facing schemas and payloads for all 20 incidents — `tests/test_toolplane.py`
- [x] Independent client check with the official MCP Inspector — `mcp.inspector.json`, `docs/week2-notes.md` section 4
- [x] The only write tool (`create_ticket`) is idempotent and fails closed without an approver — `tests/test_toolplane.py`, `docs/week2-notes.md` section 3
- [x] Runbook RAG: 16 runbooks, 48 labelled queries, 2 chunkers x 3 retrievers, recall@k reported — `src/warden/rag/`, `datasets/runbooks_v1/`, `python -m warden.rag.evaluate`, `docs/week2-notes.md` section 5
- [x] LLM re-baseline, two arms, one run each (Haiku 4.5, prompt v2) — `scripts/compare_planes.py`, `runs/w2-inproc`, `runs/w2-mcp`, `docs/week2-notes.md` section 4
- [x] `docs/week2-notes.md` (versions, findings, caveats)
- [x] `make test` green; tagged commit `w2-toolplane` (6632e78)

## Results (from `docs/week2-notes.md`)

| | in-process | MCP |
|---|---|---|
| verdict correct | 19/20 | 20/20 |
| evidence recall | 86% | 93% |
| cost / run | $0.0385 | $0.0454 |

Read as "no regression", not "MCP is better": n=1 per incident, and the plane has no mechanism to
change model behaviour.

## Known gaps carried forward

- Retrieval quality is not yet tied to end-task success (week-6 ablation row: runbook search on/off).
- I wrote both the runbooks and the queries; the queries are not a held-out set.
- The chunker comparison is unresolved at n=48.
- The write gate is still a client-side callback; week 3 replaces it with `interrupt()`.

## Verification at time of writing

90 tests pass on `main` at `f85bd95` plus the uncommitted week-3 groundwork. The offline `evalkit`
(commit `f85bd95`, 2026-10-21) was added after the `w2-toolplane` tag and belongs to week-4 prep, not
to the week-2 freeze.
