"""Small-sample statistics. n is 20 incidents and 48 queries, so every headline number needs an interval."""

from __future__ import annotations

import random
import statistics
from typing import Sequence


def mean(xs: Sequence[float]) -> float:
    return statistics.mean(xs) if xs else float("nan")


def bootstrap_ci(xs: Sequence[float], n_boot: int = 2000, alpha: float = 0.05, seed: int = 0) -> tuple:
    """Percentile bootstrap CI of the mean. Seeded, so a report is reproducible byte for byte."""
    if not xs:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    n = len(xs)
    means = sorted(sum(xs[rng.randrange(n)] for _ in range(n)) / n for _ in range(n_boot))
    return (means[int(alpha / 2 * n_boot)], means[min(n_boot - 1, int((1 - alpha / 2) * n_boot))])


def paired_diff_ci(a: Sequence[float], b: Sequence[float], **kw) -> tuple:
    """(mean(a-b), lo, hi) over per-item pairs. If the interval contains 0, the data do not separate
    the two systems. Pairing matters: both systems answer the same queries."""
    if len(a) != len(b):
        raise ValueError("paired samples must be the same length")
    d = [x - y for x, y in zip(a, b)]
    lo, hi = bootstrap_ci(d, **kw)
    return (mean(d), lo, hi)


def auroc(pos: Sequence[float], neg: Sequence[float]) -> float:
    """P(random positive scores above random negative); ties count half. 0.5 = no separation."""
    if not pos or not neg:
        return float("nan")
    wins = sum((p > q) + 0.5 * (p == q) for p in pos for q in neg)
    return wins / (len(pos) * len(neg))
