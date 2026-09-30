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

## 5. Prompt tuning: v1 vs v2

`--prompt v1` is the shipped baseline prompt (frozen; the `w1-baseline` numbers above). `--prompt v2` appends a
four-point METHOD block: compare baseline dimension by dimension, treat the alerting principal as a possible
victim, search `writes_only` across the window, and fetch and cite every supporting event including the
earliest one. It uses generic analyst method only: no scenario, principal, port or event from the dataset, so
the prompt does not leak the answer key. Replicates: v1 x3 (the baseline set plus two reruns), v2 x2, all 20
incidents each, Haiku 4.5. Reproduce with `scripts/compare_prompts.py`.

| | verdict | evidence recall | principal coverage | tool calls | cost/run |
|---|---|---|---|---|---|
| v1 (all 20) | 95% | 75% | 98% | 6.4 | $0.022 |
| v2 (all 20) | 92% | 88% | 98% | 10.0 | $0.044 |
| v1 (excl. WRD-0006/0008) | 94% | 79% | 97% | 6.4 | $0.022 |
| v2 (excl. WRD-0006/0008) | 97% | 89% | 97% | 10.0 | $0.043 |

**Dataset defect found.** WRD-0006 and WRD-0008 (noisy, false positive) have hardcoded alert-summary times
(03:12 and 06:14 UTC) and answer-key rationales ("inside the 02:00-05:00 backup window") that contradict the
generated logs (22:50-23:06 and 23:20 UTC). v1 said the activity was "within the typical 02:00-05:00 window",
which is false against the logs, and was marked right. v2 read the timestamps correctly, called it a timing
anomaly, and was marked wrong (WRD-0006 0/2). The two rows above are therefore given with and without those
incidents.

**Resolved after the comparison.** Root cause: every incident's `t0` gets a random hour, but these two scenarios
hardcode a time of day in their summary and answer key. They now pin their start time (`@starts_at` in
`scenarios.py`), the generator is `1.0.1`, and `datasets/v1` was regenerated in place. Only WRD-0006 and
WRD-0008 changed (logs and alert `detected_at`); the other 18 logs and alerts are unchanged apart from the
`generated_at` stamps in `incidents.jsonl`. **The v1/v2 numbers above were measured on the pre-fix data and were
not re-run** (cost); a single fresh pass on the fixed data is the first thing to do before trusting any
per-incident number for WRD-0006/0008. The `w1-baseline` tag still points at the unfixed dataset.

**What v2 did.** Evidence recall +13 points, and easy tier 81% to 98%. WRD-0005 flipped from 1/3 to 2/2 correct: the
dangerous mining false negative is gone. Cost and tool calls roughly double (6.4 to 10.0 calls), which is the
price of "fetch and cite everything". No stalls or budget hits in either variant (max 19 turns of 25).

**What v2 did not do.** The point-2 instruction (victim versus cause) did **not** fix WRD-0019: recall 25% to
38%, and principal coverage on the hard tier stayed at 88%, so the agent still did not reach the root-cause
principal. WRD-0017 got worse (50% to 25%). Hard-tier recall is 53% to 61%, within noise at n=2 to 3.
Prompt instructions alone do not seem to teach this model to pivot to a second principal. That is a candidate
for a structural fix in week 3 (for example a forced "who else touched this resource" step) rather than more prose.

**Caveats.** The 20 incidents are both the tuning set and the test set, so v2's gain is optimistic. Replicates are
2 to 3, so single-incident differences are noise; only the aggregate moves are worth reading. Week 4 should
add a held-out set. v2 is now the default (`--prompt v1` reproduces the baseline).
