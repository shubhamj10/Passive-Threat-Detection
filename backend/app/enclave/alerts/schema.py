"""Standard alert schemas (threat alerts and assurance alerts)."""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

ThreatClass = Literal["ddos", "botnet_c2_beaconing", "dga_domain", "dns_tunnelling"]
Severity = Literal["low", "medium", "high", "critical"]


class ModelRef(BaseModel):
    name: str
    version: str


class Evidence(BaseModel):
    features: dict[str, float]
    thresholds: dict[str, Any]
    gates_passed: list[str]
    top_shap_features: list[str]
    evidence_method: str
    context: dict[str, Any] = Field(default_factory=dict)


class DataWindow(BaseModel):
    start: str
    end: str


class Trace(BaseModel):
    config_hash: str
    data_window: DataWindow
    detector_trust_score: Optional[int] = None
    raw_score: float


class Alert(BaseModel):
    alert_id: str
    timestamp: str
    flow_id: str
    threat_class: ThreatClass
    attack_subtype: Optional[str] = None
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    entity: str
    model: ModelRef
    evidence: Evidence
    trace: Trace
    mitre_attack: str
    recommended_action: str
    ai_explanation: Optional[str] = None


class TrustScores(BaseModel):
    previous: Optional[int]
    current: int
    threshold: int


class AssuranceAlert(BaseModel):
    assurance_alert_id: str
    timestamp: str
    detector: ModelRef
    trust_score: TrustScores
    signals: dict[str, Any]
    recommended_action: str
    status: Literal["open", "resolved"] = "open"
    resolved_at: Optional[str] = None
