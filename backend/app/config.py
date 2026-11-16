"""Configuration loading and the config fingerprint used in decision traces."""
from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path

import yaml

BACKEND_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = BACKEND_DIR / "config.yaml"
MODELS_DIR = BACKEND_DIR / "models"
DATA_DIR = BACKEND_DIR / "data"
REPORTS_DIR = BACKEND_DIR / "reports"


def load_config(path: str | Path | None = None) -> dict:
    p = Path(path) if path else Path(os.environ.get("PTD_CONFIG", DEFAULT_CONFIG))
    with open(p, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@lru_cache(maxsize=1)
def get_config() -> dict:
    return load_config()


def config_hash(cfg: dict) -> str:
    """Fingerprint of the detection settings (windows, thresholds, gates, allowlist)."""
    canonical = json.dumps(cfg.get("detection", {}), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_env() -> None:
    """Load backend/.env if python-dotenv is available (optional)."""
    env = BACKEND_DIR / ".env"
    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv(env)
    except ImportError:
        if env.exists():
            for line in env.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())


def resolve(path: str | Path) -> Path:
    """Resolve a path relative to backend/ unless absolute."""
    p = Path(path)
    return p if p.is_absolute() else BACKEND_DIR / p
