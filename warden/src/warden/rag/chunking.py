"""Two chunking strategies, both recording character offsets.

fixed    naive: windows of `size` characters with `overlap`, snapped to whitespace. Knows nothing
         about headings, so a chunk can straddle two sections and a section can be split in two.
heading  structure-aware: one chunk per section, and the indexed text carries a breadcrumb
         ("<runbook title> > <heading>") so a chunk is self-describing. The breadcrumb is part of
         the strategy, not an extra: it is what structure buys you, and it is measured as such.

`Chunk.text` is what gets indexed; `Chunk.start/end` are offsets into the raw runbook text and are
what maps a chunk back to a labelled section.
"""

from __future__ import annotations

from dataclasses import dataclass

from warden.rag.corpus import Runbook


@dataclass
class Chunk:
    runbook_id: str
    start: int
    end: int
    text: str  # indexed text (may include a breadcrumb)


def fixed_chunks(rb: Runbook, size: int = 512, overlap: int = 64) -> list:
    text, n, out, pos = rb.text, len(rb.text), [], 0
    while pos < n:
        end = min(pos + size, n)
        if end < n:  # snap back to whitespace so we do not cut a word
            cut = text.rfind(" ", pos + size // 2, end)
            end = cut if cut != -1 else end
        piece = text[pos:end].strip()
        if piece:
            out.append(Chunk(rb.id, pos, end, piece))
        if end >= n:
            break
        nxt = max(end - overlap, pos + 1)
        ws = text.find(" ", nxt, end)  # start the next window on a word boundary
        pos = ws + 1 if ws != -1 else end
    return out


def heading_chunks(rb: Runbook) -> list:
    out = []
    for s in rb.sections:
        body = rb.text[s.start:s.end].strip()
        if s.heading == "title" or not body:
            continue
        # drop the "## Heading" line from the body; the breadcrumb replaces it
        lines = body.split("\n", 1)
        body = lines[1].strip() if len(lines) > 1 else body
        out.append(Chunk(rb.id, s.start, s.end, "%s > %s\n%s" % (rb.title, s.heading, body)))
    return out


def chunk_corpus(corpus: list, strategy: str, **kw) -> list:
    fn = {"fixed": fixed_chunks, "heading": heading_chunks}[strategy]
    return [c for rb in corpus for c in fn(rb, **kw)]


def sections_of(rb: Runbook, chunk: Chunk, min_overlap: int = 100) -> list:
    """Every section the chunk carries at least `min_overlap` characters of (about two sentences,
    enough to hold an answer). Generous to naive windows: a straddling chunk is credited to both
    sections. Falls back to the argmax section for a chunk too small to clear the bar."""
    hit = [s.id for s in rb.sections
           if min(chunk.end, s.end) - max(chunk.start, s.start) >= min_overlap]
    return hit or [section_of(rb, chunk)]


def section_of(rb: Runbook, chunk: Chunk) -> str:
    """The section a chunk is credited to: the one it overlaps most. Ties go to the earlier one."""
    best, best_ov = None, -1
    for s in rb.sections:
        ov = min(chunk.end, s.end) - max(chunk.start, s.start)
        if ov > best_ov:
            best, best_ov = s, ov
    return best.id
