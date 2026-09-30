"""recall@k over the labelled runbook queries: {fixed, heading} x {bm25, dense, hybrid}.

    python -m warden.rag.evaluate                       # prints the tables
    python -m warden.rag.evaluate --json out.json       # plus per-query ranks

k counts CHUNKS, because chunks are what an agent actually receives. A section is credited when any
of the top-k chunks maps to it (by character-offset overlap), so a chunker that scatters one section
across several chunks pays for it in wasted slots. recall@k is the fraction of a query's gold
sections found; with one gold section it is a hit rate.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
from collections import defaultdict

from warden.rag.chunking import chunk_corpus, section_of, sections_of
from warden.rag.corpus import DEFAULT_ROOT, all_section_ids, load_corpus
from warden.rag.retrieval import MODEL_NAME, MODEL_REVISION, build_retriever

STRATEGIES = ("fixed", "heading")
RETRIEVERS = ("bm25", "dense", "hybrid")
KS = (1, 3, 5)
TOP = 10


def load_queries(root: str, corpus: list) -> list:
    known = all_section_ids(corpus)
    out = []
    with open(os.path.join(root, "queries.jsonl"), encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                q = json.loads(line)
                bad = [g for g in q["gold"] if g not in known]
                if bad:
                    raise ValueError("%s labels unknown section(s): %s" % (q["qid"], bad))
                out.append(q)
    return out


CREDITS = ("overlap", "argmax")


def evaluate(root: str = DEFAULT_ROOT, strategies=STRATEGIES, retrievers=RETRIEVERS,
             size: int = 512, overlap: int = 64, credit: str = "overlap") -> dict:
    """credit='overlap': a chunk counts for every section it holds >=100 chars of (fair to naive
    windows). credit='argmax': a chunk counts for only its single largest section. argmax is kept
    because it exposes a flaw worth knowing about: under it, short sections can never be credited
    to any fixed chunk, so `fixed` is capped by the crediting rule, not by retrieval."""
    corpus = load_corpus(root)
    by_id = {rb.id: rb for rb in corpus}
    queries = load_queries(root, corpus)
    results = {}
    for strat in strategies:
        chunks = chunk_corpus(corpus, strat, **({"size": size, "overlap": overlap} if strat == "fixed" else {}))
        if credit == "overlap":
            sections = [sections_of(by_id[c.runbook_id], c) for c in chunks]
        else:
            sections = [[section_of(by_id[c.runbook_id], c)] for c in chunks]
        creditable = {s for ss in sections for s in ss}
        for kind in retrievers:
            retr = build_retriever(kind, chunks)
            rows = []
            for q in queries:
                ranked = retr.rank(q["query"], TOP)
                secs = [sections[i] for i, _ in ranked]  # list of section-lists, one per chunk
                gold = set(q["gold"])
                first = next((r + 1 for r, ss in enumerate(secs) if gold & set(ss)), None)
                top = lambda k: {s for ss in secs[:k] for s in ss}  # noqa: E731
                row = {"qid": q["qid"], "intent": q["intent"], "first_gold_rank": first,
                       "top5": [ss[0] for ss in secs[:5]], "gold": q["gold"]}
                for k in KS:
                    row["recall@%d" % k] = len(gold & top(k)) / len(gold)
                    row["hit@%d" % k] = int(bool(gold & top(k)))
                row["distinct_sections@5"] = len(top(5))
                rows.append(row)
            results["%s+%s" % (strat, kind)] = {
                "n_chunks": len(chunks),
                "mean_chunk_chars": round(statistics.mean(len(c.text) for c in chunks)),
                "sections_never_creditable": len({s for s in all_section_ids(corpus)
                                                  if not s.endswith("#title")} - creditable),
                "rows": rows,
            }
    return {"model": MODEL_NAME, "revision": MODEL_REVISION, "n_queries": len(queries),
            "n_sections": len(all_section_ids(corpus)), "fixed": {"size": size, "overlap": overlap},
            "credit": credit, "results": results}


def summarize(res: dict) -> str:
    n = res["n_queries"]
    lines = ["model %s @ %s | %d queries | fixed chunks %d/%d chars | credit=%s"
             % (res["model"], res["revision"][:8], n, res["fixed"]["size"], res["fixed"]["overlap"],
                res["credit"]), "",
             "| config | chunks | never-creditable sections | recall@1 | recall@3 | recall@5 | hits@1 | hits@3 | hits@5 | MRR | distinct sections in top-5 |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, r in res["results"].items():
        rows = r["rows"]
        mean = lambda key: statistics.mean(x[key] for x in rows)  # noqa: E731
        mrr = statistics.mean(1 / x["first_gold_rank"] if x["first_gold_rank"] else 0 for x in rows)
        lines.append("| %s | %d | %d | %.2f | %.2f | %.2f | %d/%d | %d/%d | %d/%d | %.2f | %.1f |" % (
            name, r["n_chunks"], r["sections_never_creditable"], mean("recall@1"), mean("recall@3"), mean("recall@5"),
            sum(x["hit@1"] for x in rows), n, sum(x["hit@3"] for x in rows), n,
            sum(x["hit@5"] for x in rows), n, mrr, mean("distinct_sections@5")))
    intents = sorted({x["intent"] for r in res["results"].values() for x in r["rows"]})
    lines += ["", "hit@3 by query intent", "",
              "| config | " + " | ".join(intents) + " |", "|---|" + "---|" * len(intents)]
    for name, r in res["results"].items():
        acc = defaultdict(list)
        for x in r["rows"]:
            acc[x["intent"]].append(x["hit@3"])
        lines.append("| %s | %s |" % (name, " | ".join("%d/%d" % (sum(acc[i]), len(acc[i])) for i in intents)))
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=DEFAULT_ROOT)
    ap.add_argument("--json")
    ap.add_argument("--size", type=int, default=512)
    ap.add_argument("--overlap", type=int, default=64)
    args = ap.parse_args()
    out = {}
    for credit in CREDITS:
        out[credit] = evaluate(args.root, size=args.size, overlap=args.overlap, credit=credit)
        print(summarize(out[credit]), "\n")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1)


if __name__ == "__main__":
    main()
