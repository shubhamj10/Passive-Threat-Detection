"""Turn labelled JSONL traffic into feature rows (labels attached AFTER extraction)."""
from __future__ import annotations

from typing import Iterable

from ..enclave.features.dns import BigramModel
from ..enclave.ingest.parser import STRIPPED_FIELDS, normalise
from ..enclave.pipeline.engine import make_extractors


def to_flow(obj: dict):
    return normalise({k: v for k, v in obj.items() if k not in STRIPPED_FIELDS}, recv_wall=0.0)


def featurize(records: Iterable[dict], cfg: dict, bigram: BigramModel) -> dict[str, list]:
    ex = make_extractors(cfg, bigram)
    rows = {k: [] for k in ex}
    lateness = float(cfg["detection"]["watermark_lateness_s"])
    max_ts, next_adv = float("-inf"), float("-inf")
    for obj in records:
        r = to_flow(obj)
        if r is None:
            continue
        max_ts = max(max_ts, r.ts)
        for e in ex.values():
            e.add(r)
        wm = max_ts - lateness
        if wm >= next_adv:
            next_adv = wm + 1.0
            for k, e in ex.items():
                rows[k].extend(e.advance(wm))
    for k, e in ex.items():
        rows[k].extend(e.flush())
    return rows
