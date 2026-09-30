"""Runbook corpus with stable section ids.

Labels are written against SECTION ids ("RB-EC2-001#benign-explanations"), which do not change
when the chunking strategy does. Every chunker records character offsets into the runbook text and
is mapped back to a section by overlap, so all strategies are graded against identical ground truth.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

DEFAULT_ROOT = os.path.join("datasets", "runbooks_v1")


def slug(heading: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", heading.lower()).strip("-")


@dataclass
class Section:
    id: str  # "RB-EC2-001#benign-explanations"
    runbook_id: str
    heading: str
    start: int  # offsets into Runbook.text, heading line included
    end: int


@dataclass
class Runbook:
    id: str
    title: str
    text: str
    sections: list = field(default_factory=list)

    def section(self, section_id: str) -> Section:
        for s in self.sections:
            if s.id == section_id:
                return s
        raise KeyError(section_id)

    def section_text(self, s: Section) -> str:
        return self.text[s.start:s.end].strip()


def parse_runbook(runbook_id: str, text: str) -> Runbook:
    m = re.match(r"#\s+(.*)", text)
    title = m.group(1).strip() if m else runbook_id
    heads = [(mm.start(), mm.group(1).strip()) for mm in re.finditer(r"(?m)^##\s+(.*)$", text)]
    sections = []
    if heads and heads[0][0] > 0:
        sections.append(Section("%s#title" % runbook_id, runbook_id, "title", 0, heads[0][0]))
    for i, (start, heading) in enumerate(heads):
        end = heads[i + 1][0] if i + 1 < len(heads) else len(text)
        sections.append(Section("%s#%s" % (runbook_id, slug(heading)), runbook_id, heading, start, end))
    return Runbook(runbook_id, title, text, sections)


def load_corpus(root: str = DEFAULT_ROOT) -> list:
    out = []
    for name in sorted(os.listdir(root)):
        if name.endswith(".md"):
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                text = fh.read().replace("\r\n", "\n")  # offsets must not depend on checkout EOLs
            out.append(parse_runbook(name[:-3], text))
    return out


def all_section_ids(corpus: list) -> set:
    return {s.id for rb in corpus for s in rb.sections}
