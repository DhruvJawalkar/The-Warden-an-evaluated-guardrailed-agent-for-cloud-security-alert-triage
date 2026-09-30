# Week 1 notes

Baseline run: `claude-haiku-4-5-20251001`, dataset `v1`, `max_steps=25`, one run per incident,
system prompt as shipped, `anthropic==1.9.0`, run on 2026-09-30 **after** `submit_verdict` started
enforcing fetched-only evidence. (A first pass before that rule gave the same verdicts; see section 4.) Regenerate the table with `python scripts/summarize_runs.py`.
Everything below is n=1 per incident. Treat it as observation, not measurement (that is week 4).

## 1. The five stubs: what I chose and why

| Stub | Choice | Reason |
|---|---|---|
| `render_tool_result` | `search_logs` becomes a pipe table under a `total_matched/returned/truncated` header, capped at 7,000 chars, with a "showing N of M, narrow the filters" note. `get_events` is JSON, 1,500 chars per record, 8,000 per result. | A table is about a third the size of JSON (7.1k vs 23.6k chars on a 100-row result). The model must be told what it did not see. |
| `handle_tool_error` | One line, kind-specific hint, 500-char cap, no traceback. From the 3rd consecutive error it tells the model to stop guessing and submit. | Recoverable errors need something to correct against. Stack traces are a token sink and an injection surface. |
| `should_stop` | `verdict_submitted`, `stalled_tool_errors` (5 in a row), `stalled_no_progress` (same call x3, or A,B,A,B,A,B). Budgets stay in `Budget.exceeded`. | Done, stuck and out-of-budget are separate eval dimensions. |
| `maybe_compact` | Trigger at 80% of `max_context_tokens`. Old `tool_result` text becomes a stub (tool, args, size, `evt-` ids seen). The newest 8/4/2 messages and the first user turn stay intact. | Only result *text* changes, never blocks, so tool_use/tool_result pairing cannot break. Ids survive so evidence can still be cited. |
| `on_budget_exhausted` | Return `None`: no forced verdict. `stop_cause` records which budget, `final_verdict` stays null. | A guessed false_positive can close a live intrusion; a guessed true_positive floods the queue. Unfinished is its own outcome. Week 3: route to the human gate. |

Also changed: `Budget.exceeded` now returns `max_context` (checked *after* compaction); `pricing_key()` maps
API ids to the price table; `.env` is loaded and `WARDEN_MAX_USD` honoured; the loop builds assistant
blocks itself if a response has empty `raw_blocks`.

## 2. Results

| Tier | n | Verdict correct | Avg model turns | Cost |
|---|---|---|---|---|
| easy | 9 | 8/9 | 5.0 | $0.200 |
| noisy | 7 | 7/7 | 5.0 | $0.172 |
| hard | 4 | 4/4 | 4.0 | $0.079 |

Total for 20 incidents: about $0.45, roughly 15k input and 1.5k output tokens per run. All 20 stopped with
`verdict_submitted`; no `submit_verdict` was rejected, and every cited id had been fetched.

**Verdict accuracy is the wrong lens. Evidence recall is where the failures are.**
Required-evidence coverage (fraction of `required_evidence_event_ids` the agent cited):

- hard tier: 100%, 33%, 25%, 75% (mean 58%), and all four verdicts were right
- easy tier: 66, 100, 50, 66, 100, 66, 100, 50, 100 (mean 78%)
- noisy tier: 100, 100, 50, 0, 100, 100, 100 (mean 79%)
- WRD-0008 (noisy, false positive): correct verdict, **0%** of required evidence cited

A week-4 harness that scores only verdict would call the hard tier perfect. It is not.

## 3. Questions from the work items

**Which tier fails most?** *(Your prediction: hard, written before reading this.)*
By verdict, easy (the only miss, WRD-0005). By evidence, hard. There is a mismatch worth understanding
before week 6: the tier labelled "hard" is not hard for this model at the verdict level.

**Noisy tier: does it call `describe_principal` unprompted?** Yes, in 7/7 noisy runs, and in all 20 overall,
almost always in the first step. But it is not unprompted: the system prompt and the tool description both
say "check the baseline first". To learn whether the model does it by itself, run once with that sentence
removed. That is a natural first ablation row.

**WRD-0019 `lambda_supply_chain`** (the work items say WRD-0020; the dataset numbers it 0019): **it stopped
at the alerting principal.** The run took 3 turns. It called `describe_principal` for `svc-lambda-invoice`
only, ran two searches on that principal, fetched one event, submitted `true_positive` with `evidence_event_ids=["evt-WRD-0019-0003"]` and
rationale "compromised credentials, misconfigured IAM policy, or lateral movement". It never looked at
`svc-ci-deploy`, which is the actual root cause (code push plus role swap 29 min earlier). Evidence recall 25%,
principals investigated 1/2. Right label, wrong reason. This is the case an eval must catch.

**WRD-0005 (the one wrong verdict):** `crypto_mining_ec2` from `svc-ci-deploy`. It read "bursty by design" in
the baseline and stopped there. Its rationale calls launches in ap-south-1 and sa-east-1 baseline-consistent,
although the answer key says those are not home regions. It ran a single search and never looked for the security-group event opening
port 3333. Verdict `false_positive`/`close_benign` on a real mining incident is the dangerous direction. The
baseline was *over-trusted*: the prompt says anomalies are relative to baseline, and the model took a
role-level "bursts are normal" as clearance for everything else about the activity.

**Where do the tokens go?** Input dominates about 10 to 1. Input grows each turn because the whole transcript
is re-sent; the last turn of a run carries roughly 3k to 8k input tokens. No run got near the 120k ceiling, so
**compaction never fired on real runs.** It is only exercised by `scripts/demo_loop.py`. **Gap:** I cannot
say which single tool result is the largest. `StepRecord` stores only a 400-char `payload_preview`, so the
run files cannot answer it. Fix: record `rendered_chars` per tool result in `StepRecord`.

**Steps versus `min_steps`:** `RunRecord.steps` counts model *turns*, and Haiku batches 2 to 3 parallel tool calls in
turn one, so turns undercount work. Hard tier: 4.0 turns on average against `min_steps` 6, which looks like
"faster than the minimum" and really means "skipped the investigation". Compare **tool calls** instead
(5 to 10 per run, 5 to 7 on the hard tier) and record both in week 4.

## 4. Things to carry into later weeks

- `submit_verdict` now enforces its own description: ids must have been fetched with `get_events`. The
  first pass of 20 runs (before the rule) had one violation, WRD-0015 citing 9 unfetched ids. The rerun
  had none, with identical verdicts on all 20 and required-evidence coverage unchanged on 18 of 20. The
  remaining spread is run-to-run noise at n=1, which is a reason to repeat runs in week 4.
- Tune the system prompt only against this table. The obvious candidate (do not treat role-level baseline
  norms as clearing region/port/scope anomalies) is a prompt fix that would probably turn WRD-0005, and
  nothing here proves it. Measure before and after on all 20.
- `--list` prints CRLF on Windows. Strip `\r` in shell loops (`| tr -d '\r'`).
- Pre-enforcement runs are kept locally in `runs/pre-enforcement/` (gitignored).
- Run the same 20 with a second model (Sonnet) before week 6, so the "before" column has a comparison.
