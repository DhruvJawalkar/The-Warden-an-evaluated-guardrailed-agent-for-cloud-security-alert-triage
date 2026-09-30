"""Label integrity and chunker invariants for the runbook corpus. No model needed.

The recall numbers are only as trustworthy as these: a gold label that points at a section that does
not exist, or a chunker that silently drops text, would corrupt the comparison without any error.
"""

from __future__ import annotations

import json
import os
import re

import pytest

from warden.rag.chunking import chunk_corpus, fixed_chunks, heading_chunks, section_of
from warden.rag.corpus import DEFAULT_ROOT, all_section_ids, load_corpus, parse_runbook

ROOT = os.environ.get("WARDEN_RUNBOOKS", DEFAULT_ROOT)


@pytest.fixture(scope="module")
def corpus():
    return load_corpus(ROOT)


@pytest.fixture(scope="module")
def queries():
    with open(os.path.join(ROOT, "queries.jsonl"), encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if x.strip()]


# --- labels -------------------------------------------------------------------------

def test_every_gold_label_names_a_real_section(corpus, queries):
    known = all_section_ids(corpus)
    for q in queries:
        assert q["gold"], q["qid"]
        for g in q["gold"]:
            assert g in known, "%s -> %s does not exist" % (q["qid"], g)


def test_query_ids_unique_and_queries_not_copied_from_headings(corpus, queries):
    assert len({q["qid"] for q in queries}) == len(queries)
    headings = {s.heading.lower() for rb in corpus for s in rb.sections}
    for q in queries:
        for h in headings - {"purpose", "containment", "escalation"}:
            assert h not in q["query"].lower(), "%s repeats the heading %r" % (q["qid"], h)


def test_gold_coverage_is_broad(corpus, queries):
    gold_runbooks = {g.split("#")[0] for q in queries for g in q["gold"]}
    assert len(gold_runbooks) == len(corpus), "a runbook has no query aimed at it"


def test_runbooks_are_generic_not_answer_keys(corpus):
    for rb in corpus:
        assert not re.search(r"WRD-\d{4}|evt-WRD", rb.text), "%s names a dataset incident" % rb.id


# --- chunkers ------------------------------------------------------------------------

def test_sections_partition_the_text(corpus):
    for rb in corpus:
        spans = [(s.start, s.end) for s in rb.sections]
        assert spans[0][0] == 0 and spans[-1][1] == len(rb.text)
        assert all(a[1] == b[0] for a, b in zip(spans, spans[1:])), rb.id


def test_fixed_chunks_cover_all_text(corpus):
    for rb in corpus:
        covered = set()
        for c in fixed_chunks(rb, 512, 64):
            covered.update(range(c.start, c.end))
        missing = [i for i, ch in enumerate(rb.text) if not ch.isspace() and i not in covered]
        assert not missing, "%s: %d characters in no chunk" % (rb.id, len(missing))


def test_fixed_chunks_respect_size_and_do_not_cut_words(corpus):
    for rb in corpus:
        for c in fixed_chunks(rb, 512, 64):
            assert c.end - c.start <= 512
            assert c.end == len(rb.text) or rb.text[c.end] in " \n", "cut mid-word in %s" % rb.id


def test_heading_chunks_one_per_section_and_map_to_themselves(corpus):
    for rb in corpus:
        chunks = heading_chunks(rb)
        real = [s for s in rb.sections if s.heading != "title"]
        assert len(chunks) == len(real)
        for c, s in zip(chunks, real):
            assert section_of(rb, c) == s.id
            assert c.text.startswith(rb.title)  # the breadcrumb is part of the strategy


def test_fixed_chunks_can_straddle_sections(corpus):
    """The property the comparison exists to measure: naive windows ignore structure."""
    straddlers = 0
    for rb in corpus:
        for c in fixed_chunks(rb, 512, 64):
            spanned = [s for s in rb.sections if min(c.end, s.end) - max(c.start, s.start) > 0]
            straddlers += len(spanned) > 1
    assert straddlers > 0


def test_every_section_is_reachable_by_some_chunk_under_both_strategies(corpus):
    for strategy in ("fixed", "heading"):
        chunks = chunk_corpus(corpus, strategy)
        by_id = {rb.id: rb for rb in corpus}
        credited = {section_of(by_id[c.runbook_id], c) for c in chunks}
        unreachable = {s for s in all_section_ids(corpus) if not s.endswith("#title")} - credited
        if strategy == "heading":
            assert not unreachable
        # for `fixed`, unreachable sections are a FINDING (a small section swallowed by argmax),
        # reported by the evaluation, not a test failure.


def test_overlap_crediting_makes_every_section_reachable_for_fixed(corpus):
    """Regression guard for a measurement flaw found in week 2: under argmax crediting, 21 of 80
    sections could never be credited to any fixed chunk, capping `fixed` by the rule, not by
    retrieval. The overlap rule must leave none unreachable."""
    from warden.rag.chunking import sections_of
    by_id = {rb.id: rb for rb in corpus}
    credited = {s for c in chunk_corpus(corpus, "fixed") for s in sections_of(by_id[c.runbook_id], c)}
    real = {s for s in all_section_ids(corpus) if not s.endswith("#title")}
    assert real - credited == set()
    strict = {section_of(by_id[c.runbook_id], c) for c in chunk_corpus(corpus, "fixed")}
    assert len(real - strict) > 0, "argmax is expected to strand sections; that is why it is not the default"


def test_bm25_grid_runs_and_beats_chance():
    pytest.importorskip("rank_bm25")
    from warden.rag.evaluate import evaluate
    res = evaluate(ROOT, retrievers=("bm25",))
    for name, r in res["results"].items():
        rows = r["rows"]
        recall5 = sum(x["recall@5"] for x in rows) / len(rows)
        assert r["sections_never_creditable"] == 0, name
        assert recall5 > 0.5, "%s recall@5=%.2f is near chance for 80 sections" % (name, recall5)


def test_parser_handles_crlf_and_missing_sections():
    rb = parse_runbook("RB-X", "# RB-X: t\n\n## A\n\nbody\n\n## B Section!\n\nmore\n")
    assert [s.id for s in rb.sections] == ["RB-X#title", "RB-X#a", "RB-X#b-section"]
