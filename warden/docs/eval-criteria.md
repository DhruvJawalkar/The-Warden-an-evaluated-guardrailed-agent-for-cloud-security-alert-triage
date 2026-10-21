# Evaluation criteria: retrieval quality and the toolset

Code: `src/warden/evalkit/` (`stats`, `retrieval`, `toolset`). Everything here runs offline; no model
calls. Week 4 builds the task-level harness on top.

```
python -m warden.evalkit.retrieval [--queries held_out.jsonl] [--json out.json]
python -m warden.evalkit.toolset runs/<dir> [--lint w1|full]
```

## 1. Retrieval quality

Graded on **distinct sections in rank order**, which is what `search_runbooks` returns. (`warden.rag.evaluate`
ranks chunks; the two views disagree, see findings.)

| metric | question it answers |
|---|---|
| recall@k, nDCG@k | is the gold section in the top k, and how high |
| runbook_hit@k | right runbook, wrong section: the agent can still open a neighbour |
| MRR | rank of the first gold section |
| chars@5 | context cost of the top-5 chunks |
| abstention AUROC, false-accept rate | does the top score tell an answerable query from an off-corpus one |
| paired nDCG@3 difference | does config A beat config B, or is it noise (paired bootstrap CI) |

Precision@k is not reported: one gold section per query caps it at 1/k.

Criteria for changing the `runbook-rag` default: a candidate must beat the reference on nDCG@3 with a paired
CI that excludes 0, **and** not lose on a held-out split. A difference whose interval contains 0 is reported
as "not separated", never as a win.

### Findings on the current data (n=48 dev queries, 12 negatives, one run, deterministic)

- **Under the server's own crediting, heading beats fixed.** A chunk is credited to its single largest-overlap
  section, as `runbook_rag._index()` does (a parity test checks the served top-5 equals the graded one). heading+hybrid
  beats every fixed-window config on nDCG@3 with CIs excluding 0 (-0.23 to -0.28). Part of this is the week-2
  `argmax` effect: short sections (e.g. "benign explanations", fixed nDCG@3 0.08 to 0.12 vs 0.51 to 0.63 for
  heading) are rarely any window's largest section, so a fixed-window server cannot return them. That is a real
  property of the deployed server, but it is a crediting-rule property, not evidence about window retrieval in
  general; `warden.rag.evaluate`'s generous overlap crediting remains the right view for that question.
- **heading+hybrid vs heading+dense: not separated** (diff -0.06, CI [-0.17, +0.04]). Hybrid's edge is runbook_hit@3 =
  1.00 (the right runbook is always in the top 3) and a higher recall@3.
- **The server default cannot abstain.** Dense top-1 scores separate on-corpus from off-corpus queries, and it holds on
  the realistic `adjacent` negatives (security topics the corpus lacks: AUROC 0.97 to 0.99, 0% false accepts).
  Hybrid does not (adjacent AUROC 0.67 to 0.69, 50% to 62% false accepts) because RRF scores track rank, not
  similarity. A hybrid retriever always hands the agent something confident-looking. Candidate fix: gate on the
  dense score inside the hybrid, or return "no good match" when dense similarity is low.
- **Weak intents**: `record` (3 queries) and `respond` (15) stay low for bm25/fixed; heading+hybrid `record` 0.17 (3 queries).

Caveats: the 48 queries and 16 runbooks have one author and are the dev set; there is **no held-out split yet**
(the `--queries` flag and per-row `split` field are ready for one, ideally written blind by someone else). The 12
negatives were written once and are few; 12 negatives make AUROC coarse. One embedding model.

## 2. Toolset

Static (no runs):

| check | rule |
|---|---|
| schema tokens | total and per tool; the surface cost paid every turn (`full` is ~1,650 tokens) |
| description | >= 60 chars; says when to use it and what comes back |
| parameters | every parameter has a description |
| names | no duplicates |

Dynamic (from saved RunRecords joined to the answer key):

| metric | reads as |
|---|---|
| calls/run, runs using, error rate and kinds, latency | usage and reliability per tool |
| rendered chars per tool, share of all chars | where context goes (new runs only) |
| **evidence funnel** | for each required evidence id: cited / fetched-not-cited / surfaced-not-fetched / never-surfaced. Splits a miss into a *reasoning*, *selection* or *search* failure |
| runbook use | searched, read, consulted the expected runbook (`datasets/eval/incident_runbooks.json`, draft labels, kept out of the tool plane's `runbooks_v1`), searched-but-never-read |
| outcome with vs without a tool | descriptive only; confounded because the agent calls tools more on hard cases |

Not claimed by these metrics: that a tool *causes* a better verdict. That is the week-6 ablation (arm with and
without the tool). Today's `w1` vs `full` comparison would also change the system prompt and task difficulty, so it
is a separate experiment.

Current state: the saved week-2 runs predate `rendered_chars` and `event_ids`, so the funnel can only separate
"cited" from "fetched, not cited" (91.5% of required ids cited) and the size figures read n/a. The first run made
after this change fills them. Static lint of `full`: `search_logs` params `aws_region` and `source_ip` have no
description; `submit_verdict` has none for `verdict`, `severity`, `recommended_action`, `evidence_event_ids`.
Those schemas were frozen byte-identical in week 2, so fixing them is a deliberate, versioned change, not a tidy-up.
