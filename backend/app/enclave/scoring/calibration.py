"""Platt calibration stored as two floats, so replays are bit-for-bit deterministic."""
from __future__ import annotations

import math

import numpy as np

_EPS = 1e-4


def _logit(p: float) -> float:
    p = min(max(p, _EPS), 1 - _EPS)
    return math.log(p / (1 - p))


class PlattCalibrator:
    def __init__(self, a: float = 1.0, b: float = 0.0):
        self.a, self.b = float(a), float(b)

    @classmethod
    def fit(cls, raw_probs, y) -> "PlattCalibrator":
        y = np.asarray(y).astype(int)
        if len(set(y.tolist())) < 2:
            return cls()  # cannot calibrate on one class: identity mapping
        from sklearn.linear_model import LogisticRegression
        x = np.array([[_logit(float(p))] for p in raw_probs])
        lr = LogisticRegression(C=100.0, solver="lbfgs", max_iter=1000)
        lr.fit(x, y)
        return cls(float(lr.coef_[0][0]), float(lr.intercept_[0]))

    def __call__(self, p: float) -> float:
        z = self.a * _logit(p) + self.b
        return 1.0 / (1.0 + math.exp(-z))

    def to_dict(self) -> dict:
        return {"a": self.a, "b": self.b}
