"""BM25, dense and hybrid retrievers over a list of Chunk.

All three expose rank(query, k) -> [(chunk_index, score)], best first.
The embedding model and its revision are pinned: an unpinned model can change under you and turn a
recall number into a moving target.
"""

from __future__ import annotations

import re

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"  # Hub head on 2026-09-30, verified via HfApi


def tokenize(text: str) -> list:
    return re.findall(r"[a-z0-9]+", text.lower())


class Bm25Retriever:
    name = "bm25"

    def __init__(self, chunks: list):
        from rank_bm25 import BM25Okapi
        self.chunks = chunks
        self.bm25 = BM25Okapi([tokenize(c.text) for c in chunks])

    def rank(self, query: str, k: int) -> list:
        scores = self.bm25.get_scores(tokenize(query))
        order = sorted(range(len(scores)), key=lambda i: (-scores[i], i))
        return [(i, float(scores[i])) for i in order[:k]]


_MODEL_CACHE: dict = {}


def load_model():
    if "m" not in _MODEL_CACHE:
        from sentence_transformers import SentenceTransformer
        _MODEL_CACHE["m"] = SentenceTransformer(MODEL_NAME, revision=MODEL_REVISION, device="cpu")
    return _MODEL_CACHE["m"]


class DenseRetriever:
    name = "dense"

    def __init__(self, chunks: list):
        self.chunks = chunks
        self.model = load_model()
        self.emb = self.model.encode([c.text for c in chunks], normalize_embeddings=True,
                                     convert_to_numpy=True, show_progress_bar=False)

    def rank(self, query: str, k: int) -> list:
        q = self.model.encode([query], normalize_embeddings=True, convert_to_numpy=True,
                              show_progress_bar=False)[0]
        scores = self.emb @ q
        order = sorted(range(len(scores)), key=lambda i: (-float(scores[i]), i))
        return [(i, float(scores[i])) for i in order[:k]]


class HybridRetriever:
    """Reciprocal rank fusion of BM25 and dense. No score calibration needed, which is the point:
    BM25 scores and cosine similarities live on unrelated scales."""

    name = "hybrid"

    def __init__(self, chunks: list, rrf_k: int = 60):
        self.chunks = chunks
        self.rrf_k = rrf_k
        self.parts = [Bm25Retriever(chunks), DenseRetriever(chunks)]

    def rank(self, query: str, k: int) -> list:
        fused: dict = {}
        for part in self.parts:
            for rank, (i, _) in enumerate(part.rank(query, len(self.chunks))):
                fused[i] = fused.get(i, 0.0) + 1.0 / (self.rrf_k + rank + 1)
        order = sorted(fused, key=lambda i: (-fused[i], i))
        return [(i, fused[i]) for i in order[:k]]


def build_retriever(kind: str, chunks: list):
    return {"bm25": Bm25Retriever, "dense": DenseRetriever, "hybrid": HybridRetriever}[kind](chunks)
