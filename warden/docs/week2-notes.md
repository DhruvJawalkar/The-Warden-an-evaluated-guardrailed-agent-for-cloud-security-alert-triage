# Week 2 notes: the tool plane

Frozen 2026-09-30: `fastmcp==4.0.10` (pulls `mcp==2.2.0`, which implements the 2026-07-28 spec),
`rank-bm25==0.2.2`, `sentence-transformers==6.1.0`, embedding model
`sentence-transformers/all-MiniLM-L6-v2` at revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`
(Hub head on the freeze date, looked up via `HfApi`, not remembered).

## 1. What was built

| Server | Tools | Notes |
|---|---|---|
| log-search | `search_logs`, `get_events` | Ported from week 1. Schemas and descriptions byte-identical (tested). |
| asset-graph | `describe_principal`; `describe_asset`, `describe_trust` | The last two read the enrichment tables. |
| threat-intel | `lookup_asn` | Static synthetic feed; noisy on purpose. |
| runbook-rag | `search_runbooks`, `get_runbook_section`, `runbook://` resources, `triage_playbook` prompt | All three MCP primitives. Default heading + hybrid. |
| ticket-writer | `create_ticket` | The only write tool. Idempotent (id = hash of incident + title). Approval-gated client side. |

`submit_verdict` stays client-side (loop control; it needs the client's set of fetched event ids).

## 2. Findings from probing FastMCP 4.0.10 before writing the port

- A returned `dict` arrives as `structured_content`, so native payloads survive and `render_tool_result`
  stays in the loop where it belongs.
- Schemas carry `additionalProperties: false`; undeclared or wrongly typed arguments come back as a
  pydantic dump with `is_error=True`. The client rejects unknown arguments first, with a message the
  model can act on, and cleans any validation dump down to `arg: reason` (no echoed input values).
- A `ToolError` message passes through verbatim, so the error `kind` travels as a `[kind] message`
  prefix. An unexpected exception leaks its message unless the server sets `mask_error_details=True`;
  all servers do. An error with no kind prefix is treated as a server bug and crashes the run,
  matching in-process behaviour.
- Server logs go to stderr; stdout is the JSON-RPC channel. Nothing prints to stdout.

## 3. Design decisions worth defending

- **`incident_id` is bound by the client and hidden from the model.** Servers are stateless and take
  it as an argument. Not exposing it means a poisoned log line cannot steer the model into reading
  another incident's logs (a cross-incident read; this is a week-5 attack class).
- **Toolsets are policy, not discovery.** `w1` is exactly the week-1 surface, so the port changes one
  variable. `full` adds tools, which also changes the system prompt (it lists tool names) and the
  task's difficulty. It is a separate experiment.
- **Writes fail closed.** A tool must declare `readOnlyHint=true` or it needs an approver; the default
  approver denies. The denial message tells the model not to retry and to describe the action in its
  rationale. Week 3 replaces the callback with a LangGraph interrupt.
- **Enrichment data is kept out of `datasets/v1`** (the tagged baseline), is generated deterministically,
  and never reads incident files or the answer key (tested). The asset table does make one hard
  incident easier (the customer-exports owner is stated), which is exactly why `full` is opt-in.

## 4. Verification

- 58 tests. Parity: identical model-facing schemas, and identical payloads across the wire for all 20
  incidents (searches, fetches, principal lookups). Error kinds survive the wire. The model cannot name
  the incident. A scripted `AgentLoop` runs unchanged over stdio. The write gate denies by default and
  the approved write is idempotent.
- The official MCP Inspector (an independent TypeScript client) lists all five servers and executes a
  `tools/call` correctly. Note it swallows a bare `python -m ...`; use `mcp.inspector.json`.
- **LLM re-baseline, two arms, one run each** (Haiku 4.5, prompt v2, fixed dataset, interleaved per
  incident; `scripts/compare_planes.py`, runs in `runs/w2-inproc` and `runs/w2-mcp`). The week-1
  numbers are not the control here: they predate the dataset fix.

  | | in-process | MCP |
  |---|---|---|
  | verdict correct | 19/20 | 20/20 |
  | evidence recall | 86% | 93% |
  | tool calls / run | 9.2 | 10.2 |
  | tool errors / run | 0.05 | 0.05 |
  | cost / run | $0.0385 | $0.0454 |
  | tool latency / run | 15 ms | 112 ms |

  All 40 runs ended `verdict_submitted`; same verdict in both arms on 19/20. **Read this as "no
  regression", not "MCP is better".** Schemas, descriptions and payloads are proven identical, so there
  is no mechanism for the plane to change model behaviour; the gaps come from single incidents where n=1
  swings (WRD-0016 verdict, WRD-0017/0019/0015 recall, WRD-0019 and WRD-0001 call counts). The +18% cost
  is those long runs. Both tool errors were model-side (an invented `session_id` filter; an invalid
  `recommended_action`) and the model recovered from each, which also exercised the new unknown-argument
  message. Only the ~100 ms/run of stdio overhead is a plane effect.

## 5. Runbook retrieval: recall@k

16 runbooks (80 sections), 48 hand-written queries in alert language, labelled at stable section ids.
Chunks map to sections by character offset, so every strategy is graded against the same truth. `k`
counts chunks (what an agent actually receives). Fixed windows: 512 chars, 64 overlap.
Reproduce: `python -m warden.rag.evaluate`.

**Crediting rule matters, and my first one was wrong.** I first credited a chunk to the single section
it overlaps most (`argmax`). Under it, 21 of 80 sections can never be credited to any fixed chunk (14
carry gold labels), mostly the short "benign explanations" sections, so `fixed` looked terrible
(2/13 on benign queries) because of my rule, not retrieval. The reported rule credits a chunk with every
section it holds at least 100 characters of (`overlap`). It is generous to `fixed`. A test guards it.

Primary table (`overlap` crediting):

| config | chunks | recall@1 | recall@3 | recall@5 | hits@3 | hits@5 | MRR | distinct sections in top-5 |
|---|---|---|---|---|---|---|---|---|
| fixed+bm25 | 59 | 0.38 | 0.74 | 0.81 | 36/48 | 39/48 | 0.59 | 8.8 |
| fixed+dense | 59 | 0.34 | 0.86 | 0.86 | 42/48 | 42/48 | 0.59 | 8.6 |
| fixed+hybrid | 59 | 0.41 | 0.80 | 0.90 | 39/48 | 44/48 | 0.65 | 8.5 |
| heading+bm25 | 80 | 0.30 | 0.65 | 0.75 | 32/48 | 37/48 | 0.51 | 5.0 |
| heading+dense | 80 | 0.31 | 0.75 | 0.90 | 37/48 | 44/48 | 0.58 | 5.0 |
| heading+hybrid | 80 | 0.36 | 0.82 | 0.88 | 41/48 | 43/48 | 0.61 | 5.0 |

For comparison, strict `argmax`: fixed rows fall to recall@5 0.52 to 0.61; heading rows are unchanged
(they cannot straddle). Both tables are printed by the harness.

What I will and will not claim:

- **Dense and hybrid beat BM25** more consistently than either chunker beats the other (hits@3 up by
  about 3 to 6 of 48 within each chunker).
- **The chunker comparison is unresolved.** Under fair crediting `fixed` is level with or ahead of
  `heading` at k=3 (dense 0.86 vs 0.75). n=48 means a difference of 3 to 4 queries is noise. Fixed
  windows also credit each chunk to ~1.7 sections, so they return more text per credited section; that
  cost (precision, tokens) is not measured here.
- **Weak spots regardless of config:** queries about what to *record* (1 to 2 of 3) and, for BM25,
  what response to *take* (7 to 8 of 15). Example: "is a burst of instance launches from a build role
  normal?" returns investigation, purpose and containment for the EC2 runbook, not benign-explanations.
- I chose `heading+hybrid` as the server default for section-granular results that pair with
  `get_runbook_section`, and the best heading-row MRR. That is a product choice, not a proven win.

Caveats: I wrote both the runbooks and the queries, so the queries are shaped by what I knew was in the
corpus (they avoid the section headings, checked by a test, but a second author would be better). The
queries are not a held-out set. One embedding model. Retrieval quality has not been measured against
end-task success; that is a week-6 ablation row (runbook search on/off).

## 6. Operational notes

- Five stdio servers take about 12s to start (each imports fastmcp). The runbook server imports torch
  and loads the model in a background warm-up thread; a first search *without* warm-up took 37s, which
  ate most of the 60s call timeout. With warm-up, a first search after normal think-time is 0.35s; an
  immediate first search is bounded at about 34s.
- Add the runbook server's latency to any week-4 cost/latency table separately: it is dominated by
  startup, not per-call work (0.1s warm).
