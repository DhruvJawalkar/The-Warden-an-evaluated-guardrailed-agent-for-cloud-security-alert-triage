# Week 1 — work items

Budget: 20 hrs. Goal: a hand-written agent loop you can defend line by line, and
a golden dataset you own.

Ship criteria (all four, or the week is not done):

- [ ] `make test` green, including the four contract tests that skip today
- [ ] `python -m warden.loop.agent_loop --incident WRD-0001` produces a verdict
- [ ] a tagged commit `w1-baseline` — week 6 benchmarks against it
- [ ] `docs/week1-notes.md`: what you chose for each of the five stubs and why

---

## Done for you

- [x] Repo scaffold, `pyproject`, `Makefile`, pytest wiring
- [x] Dataset schema with agent-visible / answer-key separation
- [x] 20-incident scenario library (9 easy, 7 noisy, 4 hard)
- [x] Deterministic generator — `make gen` reproduces byte-identically
- [x] Tool plane: `search_logs`, `get_events`, `describe_principal`, `submit_verdict`
- [x] Loop plumbing: provider adapter with transport retry, budget accounting,
      step/run records, `ScriptedClient` for offline tests
- [x] 11 dataset integrity tests + 4 contract tests waiting on your stubs

## Yours

### 1. The five stubs (~8 hrs) — `src/warden/loop/agent_loop.py`

Order matters. Each docstring carries the questions to think through.

1. `render_tool_result` — nothing runs until this exists
2. `should_stop` — then the loop terminates
3. `handle_tool_error` — then it survives bad model output
4. `maybe_compact` — hardest; make `test_compaction_preserves_tool_use_result_pairing` pass first
5. `on_budget_exhausted` — smallest, but write down your reasoning; it is a
   safety argument, not a code change

`make test` is your progress bar — skipped tests un-skip as you go.
`python -m warden.loop.agent_loop --check` lists what is left.

### 2. Wire up cost (~1 hr)

`PRICING_USD_PER_MTOK` in `agent_loop.py` is deliberately empty. Fill it from
the current pricing page. Until you do, `max_usd` cannot bind and every cost
figure is zero — which is honest, and a good habit: no invented numbers.

### 3. Run all 20 and look at the failures (~4 hrs)

No eval harness yet — that is week 4. Read the runs by hand:

```
for i in $(python -m warden.loop.agent_loop --list); do
  python -m warden.loop.agent_loop --incident $i
done
```

Then open `runs/` and answer, in `docs/week1-notes.md`:

- Which tier fails most? Predict before you look.
- On the noisy tier, does it call `describe_principal` unprompted, or does it
  close on event names alone?
- On WRD-0020 (`lambda_supply_chain`), does it investigate the *other*
  principal, or stop at the alerting one?
- Where do the tokens go? Which single tool result is largest?
- Count steps per incident against `min_steps` in the answer key.

These notes become the "before" column of your week-6 ablation table. Do not
skip them because there is no harness yet — this is the observation that tells
you what the harness needs to measure.

### 4. Tune the system prompt — carefully (~2 hrs)

`build_system_prompt` is deliberately thin. Change it if you like, but record
before/after on all 20 incidents each time. Without an eval you are moving noise
around, and the discipline of measuring now is the habit week 4 formalises.

### 5. Read the MCP spec (~3 hrs)

The `2026-07-28` specification, end to end, before week 2. Pay attention to the
stateless core, multi-round-trip requests, and what replaced the session header.
The tool plane is already written in that posture: JSON-in / JSON-out, no
session state, explicit ids. Note where that constrains the design.

### 6. Freeze and tag (~1 hr)

```
git init && git add -A && git commit -m "Warden week 1: hand-written loop + golden dataset v1"
git tag w1-baseline
```

Pin your SDK version in `pyproject.toml` and note the freeze date in the README.
The ecosystem will move under you over six weeks; the baseline must not.

---

## Deliberately not this week

MCP servers (w2), LangGraph (w3), any eval harness or OTel wiring (w4),
guardrails and the adversarial suite (w5). If you find yourself building a
retry-with-backoff-and-jitter tool-execution framework, stop — you are
rebuilding LangGraph three weeks early.
