# Week 3 — work items

Budget: 20 hrs. Goal: the week-2 loop becomes a durable LangGraph you can kill mid-run and resume,
with a human approval gate in front of the only write tool.

Ship criteria (all of them, or the week is not done):

- [ ] Graph (plan -> investigate -> verify -> report) runs all 20 incidents, one run each
- [~] Resume proven at node granularity (kill test passes); a mid-investigate kill replays that node, see week3-notes. Decision pending
- [x] `interrupt()` gate in front of `create_ticket`; approve / reject / edit paths tested
- [ ] Compaction summarises old turns; pairing-invariant test still green
- [ ] `docs/week3-notes.md` (versions, results) and `docs/week3-design.md` (why a verifier node, what was rejected)
- [ ] `make test` green; tagged commit `w3-graph`

Constraints: Haiku 4.5, prompt v2, <= $0.50 per run (ask before raising), one eval run per experiment.

---

## Done

- [x] Version freeze and pins (`docs/week3-notes.md` section 0)
- [x] Postgres 17.6 in Docker (`docker-compose.yml`), `PostgresSaver.setup()` verified

## Yours

### 1. LangGraph fundamentals and state schema (~3 hrs)
State schema (TypedDict / pydantic), reducers (`add_messages`-style append vs overwrite), conditional
edges, sub-graphs, checkpointers, `interrupt()` and `Command(resume=...)`. Write the state schema
first: what is in state (alert, plan, evidence ids, verdict, budget spent) versus recomputed. State must
be serialisable, since every superstep is checkpointed.

### 2. Graph nodes (~5 hrs)
- **plan**: produces investigation questions from the alert.
- **investigate**: wraps the existing `AgentLoop` + MCP tool plane. Keep the loop; do not rebuild it.
- **verify** (hybrid, decided): 1) deterministic checks in `graph/verify.py` (done, 11 tests):
  cited events returned by get_events, verdict/action consistent, baseline checked for the alerting
  and cited principals, resource pivot, unexamined principals. A failed check routes back to
  investigate with its `instruction`, bounded by a retry ceiling. 2) Only if they pass and
  confidence is still low: an injection guardrail over the log content/messages the LLM would
  read, then **at most one** LLM verification call per incident (`llm_verify_calls` in state,
  hard cap 1). If the guardrail trips, skip the LLM call and route to the human gate.
- **report**: assembles the verdict and routes to the gate when a write is proposed.
- Carry-over: structural fix for WRD-0019 / WRD-0017 (a "who else touched this resource" step)
  belongs in verify's gap list, not in more prompt prose.

### 3. Postgres checkpointer and the kill test (~3 hrs)
Thread id = incident id. Script: start a run, `taskkill` it mid-investigate, restart, assert it resumes
from the last checkpoint and finishes with no duplicated tool calls or double spend. Windows note:
async psycopg needs the selector event loop policy; prefer the sync saver.

### 4. Interrupt gate (~2 hrs)
Replace the client-side approver callback (`toolplane/client.py`) with `interrupt()`. Payload shows the
proposed ticket; resume with approve / reject / edit. Also route `on_budget_exhausted` to the gate
(carry-over from week 1) so "unresolved" becomes a human decision. The gate must fail closed.

### 5. Compaction by summarisation (~2 hrs)
Today `maybe_compact` elides old tool results to a stub (keeps event ids). Upgrade: when over the
threshold, replace the oldest span with a 1-2 line summary of what was established (queries run,
principals seen, event ids that matter). Open design questions: summarise with a cheap model call or
deterministically from tool-call records; evidence event ids must survive verbatim. Keep
tool_use/tool_result pairing (existing test). Behind a flag (default off for now) so week 6 can ablate on/off. Starting point: deterministic
summary built from tool-call records, event ids verbatim.

### 6. Enrich sub-agent (~2 hrs)
A sub-graph that resolves principal / asset / ASN context for the investigator, with its own
tool allowlist (read-only). Its state stays separate from the parent's.

### 7. Run all 20, compare, write up (~3 hrs)
One run per experiment. Compare to the week-2 MCP arm: verdict correct, evidence recall, calls, cost,
latency, plus resume overhead. Write `docs/week3-design.md`. Commit and tag `w3-graph`.

---

## Deliberately not this week
Eval harness and OTel (w4), adversarial suite and allowlist enforcement (w5), ablation runs (w6).
