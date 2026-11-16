"""Feature drift: Population Stability Index (PSI) of live features vs. training baseline."""
from __future__ import annotations

import math
from collections import deque

import numpy as np

_EPS = 1e-4


def make_baseline(X: np.ndarray, names: list[str], bins: int = 10) -> dict:
    """Quantile bin edges + expected bin proportions per feature (saved with the model)."""
    X = np.asarray(X, dtype=float)
    out = {}
    for j, name in enumerate(names):
        col = X[:, j]
        qs = np.quantile(col, np.linspace(0, 1, bins + 1)[1:-1])
        edges = sorted(set(float(round(q, 9)) for q in qs))
        idx = np.searchsorted(edges, col, side="right")
        props = np.bincount(idx, minlength=len(edges) + 1) / max(len(col), 1)
        out[name] = {"edges": edges, "props": props.tolist()}
    return out


def psi(expected: list[float], actual: list[float]) -> float:
    total = 0.0
    for e, a in zip(expected, actual):
        e, a = max(e, _EPS), max(a, _EPS)
        total += (a - e) * math.log(a / e)
    return total


def feature_psi(baseline: dict, name: str, values: np.ndarray) -> float:
    b = baseline[name]
    idx = np.searchsorted(b["edges"], values, side="right")
    props = np.bincount(idx, minlength=len(b["edges"]) + 1) / max(len(values), 1)
    return psi(b["props"], props.tolist())


class DriftTracker:
    """Keeps the feature vectors scored in the last `window_s` of event time."""

    def __init__(self, baseline: dict, names: list[str], window_s: float, min_samples: int,
                 max_rows: int = 20000, top_k: int = 3):
        self.baseline, self.names = baseline, names
        self.window_s = window_s
        self.buf: deque = deque(maxlen=max_rows)
        self.min_samples, self.top_k = min_samples, top_k

    def add(self, vec, ts: float) -> None:
        self.buf.append((ts, vec))

    def compute(self, now: float) -> dict | None:
        """Return {"psi": mean of the top-k feature PSIs, "top": [(feature, psi), ...]} or None."""
        while self.buf and self.buf[0][0] < now - self.window_s:
            self.buf.popleft()
        if len(self.buf) < self.min_samples:
            return None
        X = np.vstack([v for _, v in self.buf])
        per = [(n, feature_psi(self.baseline, n, X[:, j])) for j, n in enumerate(self.names) if n in self.baseline]
        per.sort(key=lambda t: -t[1])
        top = per[: self.top_k]
        return {"psi": float(np.mean([p for _, p in top])), "top": [(n, round(p, 4)) for n, p in top]}
