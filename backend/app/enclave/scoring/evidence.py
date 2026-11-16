"""Per-alert evidence: which features pushed the score up.

Uses SHAP (TreeExplainer) when the optional `shap` package is installed, otherwise
a deterministic fallback: global importance x standardised deviation from the
training mean. The method used is recorded in each alert.
"""
from __future__ import annotations

import os

import numpy as np

try:  # optional
    if os.environ.get("PTD_EVIDENCE", "auto") == "importance":
        raise ImportError
    import shap  # type: ignore
    HAVE_SHAP = True
except Exception:
    HAVE_SHAP = False


class EvidenceExplainer:
    def __init__(self, model, feature_names: list[str], means: list[float], stds: list[float]):
        self.model = model
        self.names = feature_names
        self.means = np.asarray(means, dtype=float)
        self.stds = np.asarray(stds, dtype=float)
        self.importances = np.asarray(getattr(model, "feature_importances_", np.ones(len(feature_names))))
        self._shap = None
        if HAVE_SHAP:
            try:
                self._shap = shap.TreeExplainer(model)
            except Exception:
                self._shap = None

    @property
    def method(self) -> str:
        return "shap" if self._shap is not None else "importance_deviation"

    def top_features(self, x: np.ndarray, k: int = 3) -> list[str]:
        contrib = self.contributions(x)
        order = np.argsort(-contrib, kind="stable")
        return [self.names[i] for i in order[:k]]

    def contributions(self, x: np.ndarray) -> np.ndarray:
        x = np.asarray(x, dtype=float).reshape(1, -1)
        if self._shap is not None:
            try:
                sv = self._shap.shap_values(x)
                arr = np.asarray(sv[1] if isinstance(sv, list) else sv)
                if arr.ndim == 3:        # (n, features, classes)
                    arr = arr[:, :, 1]
                return np.round(arr.reshape(-1), 10)
            except Exception:
                pass
        dev = np.abs(x.reshape(-1) - self.means) / (self.stds + 1e-9)
        return np.round(self.importances * dev, 10)
