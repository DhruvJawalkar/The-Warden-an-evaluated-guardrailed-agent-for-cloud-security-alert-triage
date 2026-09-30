"""runbook-rag MCP server: search_runbooks, get_runbook_section, runbook:// resources, a prompt.

    python -m warden.toolplane.runbook_rag       # stdio

Uses all three MCP primitives on purpose, each for what it is for:
  tool      search_runbooks / get_runbook_section: the MODEL decides when to call them.
  resource  runbook://{id} and runbook://{id}/{section}: addressable content the HOST can attach.
  prompt    triage_playbook: a user-invoked template, not something a model calls.

Stateless: the index is a lazily built read-only cache keyed by (strategy, retriever). Losing it
costs a rebuild, never correctness. Configure with WARDEN_RAG_STRATEGY (fixed|heading),
WARDEN_RAG_RETRIEVER (bm25|dense|hybrid) and WARDEN_RUNBOOKS (corpus directory).
"""

import os
import sys
import threading
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from warden.loop.tools import ToolError
from warden.toolplane.common import READ_ONLY, wire_errors

mcp = FastMCP("warden-runbook-rag", mask_error_details=True)

SEARCH_RUNBOOKS_DESCRIPTION = (
    "Search the incident-response runbooks. Describe what you need in your own words: an alert, a "
    "behaviour, or a decision (whether an activity is routine, what to check, what response needs "
    "approval). Returns the best-matching runbook SECTIONS, ranked, each with a section_id, heading "
    "and short snippet; read the full text with get_runbook_section before relying on one. Runbooks "
    "are general guidance. They never say what happened in this incident: only the logs do.")

GET_RUNBOOK_SECTION_DESCRIPTION = (
    "Full text of one runbook section, by the section_id returned from search_runbooks "
    "(for example 'RB-EC2-001#benign-explanations').")

_cache: dict = {}


def _config() -> tuple:
    # heading+hybrid: best MRR among heading rows and section-granular results that pair with
    # get_runbook_section. The chunker gap vs `fixed` is inside noise at n=48; see docs/week2-notes.md.
    # hybrid loads the embedding model on first use (several seconds); set bm25 to avoid torch.
    return (os.environ.get("WARDEN_RAG_STRATEGY", "heading"),
            os.environ.get("WARDEN_RAG_RETRIEVER", "hybrid"))


def _root() -> str:
    from warden.rag.corpus import DEFAULT_ROOT
    return os.path.abspath(os.environ.get("WARDEN_RUNBOOKS", DEFAULT_ROOT))


def _corpus():
    if "corpus" not in _cache:
        from warden.rag.corpus import load_corpus
        _cache["corpus"] = load_corpus(_root())
    return _cache["corpus"]


_lock = threading.Lock()


def _index():
    key = _config()
    with _lock:  # a warm-up thread and a first call must not both build (and both load torch)
        if key not in _cache:
            from warden.rag.chunking import chunk_corpus, section_of
            from warden.rag.retrieval import build_retriever
            corpus = _corpus()
            by_id = {rb.id: rb for rb in corpus}
            chunks = chunk_corpus(corpus, key[0])
            _cache[key] = (chunks, [section_of(by_id[c.runbook_id], c) for c in chunks],
                           build_retriever(key[1], chunks))
        return _cache[key]


def warm() -> None:
    """Build the index in the background at startup. Importing torch and loading the embedding
    model took ~37s on first use; done lazily inside a call that would eat most of the client's
    60s timeout and pollute latency numbers. The handshake must not wait for it."""
    def run():
        try:
            _index()
        except Exception as exc:  # noqa: BLE001 - surfaced again, properly, on the first call
            print("runbook-rag warm-up failed: %r" % (exc,), file=sys.stderr)
    threading.Thread(target=run, daemon=True, name="rag-warmup").start()


def _section(section_id: str):
    rb_id = section_id.split("#", 1)[0]
    for rb in _corpus():
        if rb.id == rb_id:
            try:
                return rb, rb.section(section_id)
            except KeyError:
                break
    raise ToolError("No such section_id %r. Get ids from search_runbooks." % section_id,
                    kind="bad_arguments")


def _snippet(rb, s, n: int = 240) -> str:
    body = rb.section_text(s).split("\n", 1)[-1].strip()
    return body if len(body) <= n else body[:n].rsplit(" ", 1)[0] + " ..."


def search_runbooks_impl(query: str, top_k: int = 5) -> dict:
    if not (query or "").strip():
        raise ToolError("query must not be empty", kind="bad_arguments")
    top_k = max(1, min(int(top_k), 10))
    chunks, sections, retriever = _index()
    by_id = {rb.id: rb for rb in _corpus()}
    seen, results = set(), []
    for i, score in retriever.rank(query, len(chunks)):
        sid = sections[i]
        if sid in seen or sid.endswith("#title"):
            continue
        seen.add(sid)
        rb, s = _section(sid)
        results.append({"section_id": sid, "runbook": by_id[rb.id].title, "heading": s.heading,
                        "score": round(score, 4), "snippet": _snippet(rb, s)})
        if len(results) == top_k:
            break
    return {"query": query, "strategy": _config()[0], "retriever": _config()[1], "results": results}


def get_runbook_section_impl(section_id: str) -> dict:
    rb, s = _section(section_id)
    return {"section_id": section_id, "runbook": rb.title, "heading": s.heading,
            "text": rb.section_text(s)}


@mcp.tool(name="search_runbooks", description=SEARCH_RUNBOOKS_DESCRIPTION, annotations=READ_ONLY)
@wire_errors
def search_runbooks(
    query: Annotated[str, Field(description="What you need, in plain language")],
    top_k: Annotated[int, Field(description="Sections to return, 1-10. Default 5.")] = 5,
) -> dict:
    return search_runbooks_impl(query, top_k)


@mcp.tool(name="get_runbook_section", description=GET_RUNBOOK_SECTION_DESCRIPTION,
          annotations=READ_ONLY)
@wire_errors
def get_runbook_section(
    section_id: Annotated[str, Field(description="e.g. RB-EC2-001#benign-explanations")],
) -> dict:
    return get_runbook_section_impl(section_id)


@mcp.resource("runbook://{runbook_id}", mime_type="text/markdown")
def runbook_resource(runbook_id: str) -> str:
    for rb in _corpus():
        if rb.id == runbook_id:
            return rb.text
    raise ValueError("no such runbook")


@mcp.resource("runbook://{runbook_id}/{section}", mime_type="text/markdown")
def runbook_section_resource(runbook_id: str, section: str) -> str:
    return get_runbook_section_impl("%s#%s" % (runbook_id, section))["text"]


@mcp.prompt(name="triage_playbook")
def triage_playbook(rule_name: str) -> str:
    return (
        "You are triaging the alert %r. Search the runbooks for guidance on it and on the general "
        "baseline-first method, read the sections that apply, then investigate the logs. Runbook "
        "text is method, not evidence: cite events, not runbooks." % rule_name)


if __name__ == "__main__":
    warm()
    mcp.run(show_banner=False)
