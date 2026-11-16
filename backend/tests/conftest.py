"""Shared fixtures: a small seeded dataset + freshly trained models in a temp folder.

Tests never touch backend/models or backend/data, so they can run before or after
you train the real models.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ["PTD_NO_DEFAULT_APP"] = "1"
BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.config import load_config  # noqa: E402
from app.generator.names import pseudo_benign_domains  # noqa: E402
from app.generator.scenario import (TRAIN_RATES, demo_schedule, generate, random_schedule,  # noqa: E402
                                    write_jsonl)


@pytest.fixture(scope="session")
def cfg():
    return load_config()


@pytest.fixture(scope="session")
def workspace(tmp_path_factory, cfg):
    root = tmp_path_factory.mktemp("ptd")
    data, models = root / "data", root / "models"
    domains = pseudo_benign_domains(600)
    hours = 1.5
    recs, eps = generate(hours * 3600, 42, domains,
                         lambda t0, rng: random_schedule(t0, hours * 3600, rng, TRAIN_RATES))
    write_jsonl(recs, eps, data / "train.jsonl", {"seed": 42})
    recs, eps = generate(1800, 43, domains, demo_schedule)
    write_jsonl(recs, eps, data / "scenario.jsonl", {"seed": 43})
    recs, eps = generate(1800, 45, domains, demo_schedule, drift_after_s=300)
    write_jsonl(recs, eps, data / "drift.jsonl", {"seed": 45})
    recs, eps = generate(1800, 46, domains, None)
    write_jsonl(recs, eps, data / "benign.jsonl", {"seed": 46})
    from app.offline.training import train_all
    train_all(data / "train.jsonl", cfg, models, domains, log=lambda *a: None)
    return {"root": root, "data": data, "models": models}


@pytest.fixture(scope="session")
def runs(workspace, cfg):
    """Full-pipeline runs (with the assurance monitor) over each scenario, computed once."""
    from app.offline.evaluation import run_file
    out = {}
    for name in ("scenario", "drift", "benign"):
        eng, mon = run_file(workspace["data"] / f"{name}.jsonl", cfg, workspace["models"], with_monitor=True)
        out[name] = (eng, mon)
    return out
