"""Pluggable detector interface + model bundle loading.

A detector turns closed FeatureRows into Candidates. Its scoring, threat-class
rule and validation gates are PURE functions of (features, context, thresholds),
which is what makes every alert replayable from its decision trace.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np

from ...config import MODELS_DIR
from ..features.common import FeatureRow
from ..scoring.calibration import PlattCalibrator
from ..scoring.evidence import EvidenceExplainer


@dataclass
class Candidate:
    detector: str
    threat_class: str
    row: FeatureRow
    raw_prob: float
    confidence: float
    entity: str
    thresholds: dict
    context: dict
    gates_passed: list[str] = field(default_factory=list)
    gates_failed: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.gates_failed and self.confidence >= self.thresholds["alert_threshold"]


def registry_path(models_dir: Path | None = None) -> Path:
    return (models_dir or MODELS_DIR) / "registry.json"


def load_registry(models_dir: Path | None = None) -> dict:
    p = registry_path(models_dir)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def bundle_path(name: str, version: str, models_dir: Path | None = None) -> Path:
    return (models_dir or MODELS_DIR) / f"{name}-{version}.joblib"


def load_bundle(name: str, version: str | None = None, models_dir: Path | None = None) -> dict:
    version = version or load_registry(models_dir).get(name)
    if not version:
        raise FileNotFoundError(f"no trained model for {name}: run scripts/train.py")
    p = bundle_path(name, version, models_dir)
    if not p.exists():
        raise FileNotFoundError(f"model file missing: {p}")
    return joblib.load(p)


class Detector:
    name = "base"
    cfg_key = "base"

    def __init__(self, bundle: dict, cfg: dict):
        self.bundle = bundle
        self.cfg = cfg
        self.dcfg = cfg["detection"][self.cfg_key]
        self.version = bundle["version"]
        self.feature_names: list[str] = bundle["feature_names"]
        self.model = bundle["model"]
        self.calibrator = PlattCalibrator(**bundle["calibrator"])
        self.explainer = EvidenceExplainer(self.model, self.feature_names, bundle["means"], bundle["stds"])
        allow = cfg["detection"].get("allowlist", {}) or {}
        self.allow_dst = set(allow.get("destinations") or [])
        self.allow_domains = set(allow.get("domains") or [])
        self.last_normal: list = []

    # ---- pure scoring --------------------------------------------------
    def vectorise(self, features: dict) -> np.ndarray:
        return np.array([float(features[n]) for n in self.feature_names], dtype=float)

    def raw_probs(self, X: np.ndarray) -> np.ndarray:
        if len(X) == 0:
            return np.zeros(0)
        return self.model.predict_proba(X)[:, 1]

    def calibrate(self, p: float) -> float:
        return round(self.calibrator(float(p)), 4)

    def score_features(self, features: dict) -> tuple[float, float]:
        raw = float(self.raw_probs(self.vectorise(features).reshape(1, -1))[0])
        return raw, self.calibrate(raw)

    def top_features(self, features: dict) -> list[str]:
        return self.explainer.top_features(self.vectorise(features))

    # ---- to implement ----------------------------------------------------
    def thresholds(self) -> dict:
        raise NotImplementedError

    @staticmethod
    def classify(features: dict, thresholds: dict) -> tuple[str, str | None]:
        """Return (threat_class, subtype)."""
        raise NotImplementedError

    @staticmethod
    def gates(threat_class: str, features: dict, context: dict, thresholds: dict) -> tuple[list, list]:
        raise NotImplementedError

    def process(self, rows: list[FeatureRow]) -> list[Candidate]:
        raise NotImplementedError

    # ---- metadata ---------------------------------------------------------
    MITRE: dict = {}
    ACTIONS: dict = {}

    def mitre(self, threat_class: str, subtype: str | None) -> str:
        return self.MITRE.get(subtype) or self.MITRE.get(threat_class, "")

    def action(self, threat_class: str, subtype: str | None) -> str:
        return self.ACTIONS.get(subtype) or self.ACTIONS.get(threat_class, "Analyst review")

    def _scored(self, rows: list[FeatureRow]) -> list[tuple[FeatureRow, float, float]]:
        if not rows:
            return []
        X = np.vstack([self.vectorise(r.features) for r in rows])
        raws = self.raw_probs(X)
        out = [(r, float(p), self.calibrate(p)) for r, p in zip(rows, raws)]
        # rows the model judged normal, with their vectors: used for drift monitoring
        thr = self.dcfg["alert_threshold"]
        self.last_normal = [(r, x) for (r, _, c), x in zip(out, X) if c < thr]
        return out


def make_detectors(cfg: dict, models_dir: Path | None = None) -> dict[str, Detector]:
    from .beacon import BeaconDetector
    from .ddos import DdosDetector
    from .dns import DnsDetector
    out = {}
    for cls in (DdosDetector, BeaconDetector, DnsDetector):
        out[cls.name] = cls(load_bundle(cls.name, models_dir=models_dir), cfg)
    return out


def detector_class(name: str):
    from .beacon import BeaconDetector
    from .ddos import DdosDetector
    from .dns import DnsDetector
    return {c.name: c for c in (DdosDetector, BeaconDetector, DnsDetector)}[name]
