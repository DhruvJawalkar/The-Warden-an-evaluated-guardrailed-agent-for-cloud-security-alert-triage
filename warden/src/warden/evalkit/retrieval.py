"""Retrieval-quality metrics for the runbook corpus, measured the way the agent receives results.

    python -m warden.evalkit.retrieval                         # tables
    python -m warden.evalkit.retrieval --json out.json         # plus per-query rows
    python -m warden.evalkit.retrieval --queries extra.jsonl   # add a (held-out) query file

`warden.rag.evaluate` ranks CHUNKS. The `search_runbooks` tool does not return chunks: it returns
distinct SECTIONS in rank order, so that is the ranking graded here. A chunk is credited to its single
largest-overlap section (`section_of`), exactly as the server's index does, so a straddling fixed window
is judged by the section it mostly holds; `warden.rag.evaluate`'s generous multi-section crediting
is a different, chunk-level question. Metrics (per query, then
averaged with a bootstrap CI):

  recall@k       fraction of gold sections in the top-k sections
  ndcg@k         binary-gain nDCG; rewards putting the gold section first, not just somewhere
  runbook_hit@k  the gold RUNBOOK is in the top-k, even if the section is wrong. A softer success:
                 the agent can still call get_runbook_section on a neighbour
  MRR            1 / rank of the first gold section
  chars@5        characters in the top-5 chunks: what a chunk-granular consumer pays for that recall

Precision@k is deliberately absent: with one gold section per query it is capped at 1/k, which says
nothing about quality.

Abstention. A retriever always returns something; the question is whether its top score tells a real
query from one the corpus cannot answer (`queries_negative.jsonl`, gold = []). Reported as the AUROC
of the top-1 score (positives vs negatives; 0.5 = no signal) and the false-accept rate at the
threshold that still accepts 90% of the positives. Hybrid scores are reciprocal-rank-fusion values,
which depend on rank, not similarity, so expect hybrid to carry little abstention signal.
"""

from __future__ import annotations

import argparse
import json
import math
import os
from collections import defaultdict

from warden.evalkit.stats import auroc, bootstrap_ci, mean, paired_diff_ci

KS = (1, 3, 5)
REFERENCE = "heading+hybrid"  # the runbook-rag server default; other configs are diffed against it
METRICS = ("recall@1", "recall@3", "recall@5", "ndcg@3", "ndcg@5", "runbook_hit@3", "mrr")


# --- pure metrics (no model, no corpus) ------------------------------------------------------

def dedupe_sections(per_chunk_sections: list) -> list:
    """Chunk-ranked list of section lists -> distinct sections in first-appearance order, minus
    `#title` pseudo-sections. This is exactly what search_runbooks returns to the agent."""
    seen, out = set(), []
    for secs in per_chunk_sections:
        for s in secs:
            if s not in seen and not s.endswith("#title"):
                seen.add(s)
                out.append(s)
    return out


def recall_at_k(ranked: list, gold: set, k: int) -> float:
    return len(gold & set(ranked[:k])) / len(gold) if gold else float("nan")


def ndcg_at_k(ranked: list, gold: set, k: int) -> float:
    if not gold:
        return float("nan")
    dcg = sum(1 / math.log2(i + 2) for i, s in enumerate(ranked[:k]) if s in gold)
    ideal = sum(1 / math.log2(i + 2) for i in range(min(len(gold), k)))
    return dcg / ideal


def reciprocal_rank(ranked: list, gold: set) -> float:
    return next((1 / (i + 1) for i, s in enumerate(ranked) if s in gold), 0.0)


def runbook_hit_at_k(ranked: list, gold: set, k: int) -> float:
    books = {g.split("#", 1)[0] for g in gold}
    return float(any(s.split("#", 1)[0] in books for s in ranked[:k]))


def accept_threshold(pos_scores: list, keep: float = 0.9) -> float:
    """Highest threshold that still accepts `keep` of the positive queries."""
    s = sorted(pos_scores)
    return s[min(len(s) - 1, int((1 - keep) * len(s)))]


def abstention(pos_scores: list, neg_scores: list, keep: float = 0.9) -> dict:
    if not neg_scores or not pos_scores:
        return {}
    thr = accept_threshold(pos_scores, keep)
    return {"auroc": auroc(pos_scores, neg_scores), "n_pos": len(pos_scores), "n_neg": len(neg_scores),
            "false_accept_rate": sum(s >= thr for s in neg_scores) / len(neg_scores), "keep": keep}


# --- harness ---------------------------------------------------------------------------------

def load_jsonl(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if x.strip()]


def evaluate(root: str = None, extra_queries: tuple = (), strategies=("fixed", "heading"),
             retrievers=("bm25", "dense", "hybrid"), size: int = 512, overlap: int = 64) -> dict:
    from warden.rag.chunking import chunk_corpus, section_of
    from warden.rag.corpus import DEFAULT_ROOT, all_section_ids, load_corpus
    from warden.rag.retrieval import MODEL_NAME, MODEL_REVISION, build_retriever

    root = root or DEFAULT_ROOT
    corpus = load_corpus(root)
    by_id = {rb.id: rb for rb in corpus}
    known = all_section_ids(corpus)
    queries = [dict(q, split=q.get("split", "dev")) for q in load_jsonl(os.path.join(root, "queries.jsonl"))]
    for path in extra_queries:
        queries += [dict(q, split=q.get("split", os.path.basename(path))) for q in load_jsonl(path)]
    neg_path = os.path.join(root, "queries_negative.jsonl")
    negatives = load_jsonl(neg_path) if os.path.exists(neg_path) else []
    for q in queries:
        bad = [g for g in q["gold"] if g not in known]
        if bad or not q["gold"]:
            raise ValueError("%s: gold must be non-empty known sections (got %s)" % (q["qid"], q["gold"]))
    for q in negatives:
        if q["gold"]:
            raise ValueError("%s: a negative query must have gold = []" % q["qid"])

    results = {}
    for strat in strategies:
        chunks = chunk_corpus(corpus, strat, **({"size": size, "overlap": overlap} if strat == "fixed" else {}))
        sections = [[section_of(by_id[c.runbook_id], c)] for c in chunks]  # one section per chunk, as the server does
        for kind in retrievers:
            retr = build_retriever(kind, chunks)

            def run(q):
                ranked_chunks = retr.rank(q["query"], len(chunks))
                return ranked_chunks, dedupe_sections([sections[i] for i, _ in ranked_chunks])

            rows, pos_scores = [], []
            for q in queries:
                rc, ranked = run(q)
                gold = set(q["gold"])
                row = {"qid": q["qid"], "intent": q["intent"], "split": q["split"], "gold": q["gold"],
                       "top5": ranked[:5], "mrr": reciprocal_rank(ranked, gold),
                       "chars@5": sum(len(chunks[i].text) for i, _ in rc[:5])}
                for k in KS:
                    row["recall@%d" % k] = recall_at_k(ranked, gold, k)
                    row["ndcg@%d" % k] = ndcg_at_k(ranked, gold, k)
                    row["runbook_hit@%d" % k] = runbook_hit_at_k(ranked, gold, k)
                rows.append(row)
                pos_scores.append(rc[0][1])
            neg = [(q["intent"], run(q)[0][0][1]) for q in negatives]
            abst = abstention(pos_scores, [sc for _, sc in neg])
            if abst:  # "adjacent" negatives are security-flavoured; "unrelated" ones are trivially easy
                abst["by_intent"] = {i: abstention(pos_scores, [sc for j, sc in neg if j == i])
                                     for i in sorted({i for i, _ in neg})}
            results["%s+%s" % (strat, kind)] = {"n_chunks": len(chunks), "rows": rows, "abstention": abst}
    return {"model": MODEL_NAME, "revision": MODEL_REVISION, "n_queries": len(queries),
            "n_negative": len(negatives), "fixed": {"size": size, "overlap": overlap}, "results": results}


# --- reporting -------------------------------------------------------------------------------

def _fmt(xs: list) -> str:
    lo, hi = bootstrap_ci(xs)
    return "%.2f [%.2f, %.2f]" % (mean(xs), lo, hi)


def summarize(res: dict) -> str:
    out = ["model %s @ %s | %d queries | %d negative | section-level ranking, 95%% bootstrap CIs"
           % (res["model"], res["revision"][:8], res["n_queries"], res["n_negative"]), ""]
    out += ["| config | " + " | ".join(METRICS) + " | chars@5 |", "|---|" + "---|" * (len(METRICS) + 1)]
    for name, r in res["results"].items():
        cells = [_fmt([x[m] for x in r["rows"]]) for m in METRICS]
        out.append("| %s | %s | %d |" % (name, " | ".join(cells), mean([x["chars@5"] for x in r["rows"]])))

    ref = res["results"].get(REFERENCE)
    if ref:
        out += ["", "ndcg@3 paired difference vs %s (config minus reference; interval containing 0 = not separated)"
                % REFERENCE, "", "| config | diff | 95% CI | separated? |", "|---|---|---|---|"]
        for name, r in res["results"].items():
            if name == REFERENCE:
                continue
            d, lo, hi = paired_diff_ci([x["ndcg@3"] for x in r["rows"]], [x["ndcg@3"] for x in ref["rows"]])
            out.append("| %s | %+.3f | [%+.3f, %+.3f] | %s |" % (name, d, lo, hi, "yes" if lo > 0 or hi < 0 else "no"))

    first = next(iter(res["results"].values()))["rows"]
    intents = sorted({x["intent"] for x in first})
    counts = defaultdict(int)
    for x in first:
        counts[x["intent"]] += 1
    out += ["", "mean ndcg@3 by query intent (n in header)", "",
            "| config | " + " | ".join("%s (%d)" % (i, counts[i]) for i in intents) + " |",
            "|---|" + "---|" * len(intents)]
    for name, r in res["results"].items():
        acc = defaultdict(list)
        for x in r["rows"]:
            acc[x["intent"]].append(x["ndcg@3"])
        out.append("| %s | %s |" % (name, " | ".join("%.2f" % mean(acc[i]) for i in intents)))

    splits = sorted({x["split"] for x in first})
    if len(splits) > 1:
        out += ["", "ndcg@3 by query split (a held-out gap vs dev means the config was tuned to dev)", "",
                "| config | " + " | ".join(splits) + " |", "|---|" + "---|" * len(splits)]
        for name, r in res["results"].items():
            acc = defaultdict(list)
            for x in r["rows"]:
                acc[x["split"]].append(x["ndcg@3"])
            out.append("| %s | %s |" % (name, " | ".join("%s (n=%d)" % (_fmt(acc[s]), len(acc[s])) for s in splits)))

    if any(r["abstention"] for r in res["results"].values()):
        out += ["", "abstention: does the top-1 score separate answerable queries from off-corpus ones?",
                "adjacent = security topics the corpus does not cover (the realistic case); unrelated = trivially off-topic", "",
                "| config | AUROC all | AUROC adjacent | AUROC unrelated | false-accept at 90% positive acceptance (all / adjacent) |",
                "|---|---|---|---|---|"]
        for name, r in res["results"].items():
            a = r["abstention"]
            bi = a["by_intent"]
            f = lambda k, key: "%.2f" % bi[k][key] if k in bi else "n/a"  # noqa: E731
            out.append("| %s | %.2f | %s | %s | %.2f / %s |" % (name, a["auroc"], f("adjacent", "auroc"),
                                                                f("unrelated", "auroc"), a["false_accept_rate"],
                                                                f("adjacent", "false_accept_rate")))
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root")
    ap.add_argument("--queries", action="append", default=[],
                    help="extra query file(s); a per-row `split` is honoured")
    ap.add_argument("--json")
    args = ap.parse_args()
    res = evaluate(args.root, tuple(args.queries))
    print(summarize(res))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=1)


if __name__ == "__main__":
    main()
