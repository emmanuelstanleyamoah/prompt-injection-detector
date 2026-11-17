from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from detector.normalize import normalize

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"

LEVEL_POINTS = {
    "critical": 40,
    "high": 30,
    "medium": 15,
    "low": 8,
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    level: str
    points: int
    phrases: tuple[str, ...]
    surfaces: tuple[str, ...]
    path: str


@lru_cache(maxsize=4)
def load_rules(directory: Path | None = None) -> list[Rule]:
    folder = directory or RULES_DIR
    rules: list[Rule] = []
    for path in sorted(folder.glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        selection = document["detection"]["selection"]
        raw_phrases = selection.get("prompt|contains")
        if not raw_phrases:
            raise ValueError(f"{path.name} has no prompt|contains selection")
        level = str(document["level"])
        if level not in LEVEL_POINTS:
            raise ValueError(f"{path.name} has unsupported level {level}")
        surfaces = tuple(str(phrase) for phrase in raw_phrases)
        phrases = tuple(normalize(phrase) for phrase in surfaces)
        rules.append(
            Rule(
                id=str(document["id"]),
                title=str(document["title"]),
                level=level,
                points=LEVEL_POINTS[level],
                phrases=phrases,
                surfaces=surfaces,
                path=path.name,
            )
        )
    if not rules:
        raise FileNotFoundError(f"no Sigma rules in {folder}")
    return rules
