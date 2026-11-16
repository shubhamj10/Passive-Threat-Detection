"""Domain names for synthetic DNS traffic (reserved .example / .test style names)."""
from __future__ import annotations

import random
import string
from pathlib import Path

WORDS = """news cloud shop portal mail video music photo travel bank weather sport game market health
learn code data stream store book food home city green blue river stone light star north south
east west media pixel daily smart fast secure open link social office team work school study
office drive maps chat play search docs forum blog wiki times post press radio tv film art design
garden kitchen auto motor bike train fly air sea sun moon cloudy rain snow fresh bright global local
metro urban rural farm craft maker build tools tech labs hub zone point base core net web site
online world planet region nation union group partner client service support help care life""".split()

TLDS = ["example", "test"]
SUBS = ["www", "api", "cdn", "mail", "static", "img", "login", "m"]


def pseudo_benign_domains(n: int, seed: int = 7) -> list[str]:
    rng = random.Random(seed)
    out = set()
    while len(out) < n:
        k = rng.choice([1, 2, 2, 2])
        words = rng.sample(WORDS, k)
        sep = rng.choice(["", "", "-"])
        sld = sep.join(words)
        if rng.random() < 0.08:
            sld += str(rng.randint(1, 99))
        out.add(f"{sld}.{rng.choice(TLDS)}")
    return sorted(out)


def load_benign_domains(path: Path, n_fallback: int = 600, seed: int = 7) -> tuple[list[str], bool]:
    """Return (domains, from_file). Accepts Tranco-style 'rank,domain' or one domain per line."""
    if path.exists():
        doms = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            d = line.split(",")[-1].strip().rstrip(".")
            if "." in d:
                doms.append(d)
        if doms:
            return doms[:20000], True
    return pseudo_benign_domains(n_fallback, seed), False


def dga_domain(rng: random.Random) -> str:
    n = rng.randint(10, 20)
    alphabet = string.ascii_lowercase + (string.digits if rng.random() < 0.3 else "")
    return "".join(rng.choice(alphabet) for _ in range(n)) + "." + rng.choice(["example", "test", "invalid"])


B32 = string.ascii_lowercase + "234567"


def tunnel_query(rng: random.Random, base: str, seq: int) -> str:
    chunk = "".join(rng.choice(B32) for _ in range(rng.randint(38, 60)))
    return f"{chunk}.s{seq % 1000}.{base}"
