"""Trust score (0-100) per detector from drift, alert volume and analyst feedback."""
from __future__ import annotations

import math


def drift_component(psi: float, warn: float) -> float:
    lo, hi = warn / 2, warn * 2.5
    if psi <= lo:
        return 1.0
    if psi >= hi:
        return 0.0
    return 1.0 - (psi - lo) / (hi - lo)


def volume_component(ratio: float, band: list[float], expected: float) -> float:
    lo, hi = band
    if ratio > hi:
        return max(0.0, 1.0 - math.log(ratio / hi) / math.log(4))
    if ratio < lo and expected >= 3:
        # silence is weaker evidence of failure than a flood: at most halve this signal
        return 0.5 + 0.5 * max(0.0, ratio / lo)
    return 1.0


def feedback_component(fp_rate: float) -> float:
    return max(0.0, 1.0 - fp_rate / 0.5)


def combine(components: dict[str, float | None], weights: dict[str, float]) -> int | None:
    """Weighted mean over the signals that have enough data; None = insufficient data."""
    num = den = 0.0
    for k, v in components.items():
        if v is None:
            continue
        num += weights[k] * v
        den += weights[k]
    if den == 0:
        return None
    return int(round(100 * num / den))
