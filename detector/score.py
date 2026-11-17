from __future__ import annotations

from dataclasses import dataclass, field

from detector.normalize import normalize
from detector.rules import Rule, load_rules

# One high-severity rule is 30 points. The published operating point
# blocks at 25, so a single high rule is enough and a medium rule is not.
THRESHOLD = 25


@dataclass(frozen=True)
class RuleHit:
    id: str
    title: str
    points: int
    phrase: str


@dataclass(frozen=True)
class Score:
    score: int
    blocked: bool
    threshold: int
    normalized: str
    hits: tuple[RuleHit, ...] = field(default_factory=tuple)

    @property
    def rule_ids(self) -> list[str]:
        return [hit.id for hit in self.hits]


def score_prompt(
    text: str,
    rules: list[Rule] | None = None,
    threshold: int = THRESHOLD,
) -> Score:
    """Score one prompt. Points add once per matched rule, not per phrase."""
    loaded = rules if rules is not None else load_rules()
    folded = normalize(text)
    hits: list[RuleHit] = []
    for rule in loaded:
        matched = next((phrase for phrase in rule.phrases if phrase in folded), None)
        if matched is None:
            continue
        hits.append(
            RuleHit(
                id=rule.id,
                title=rule.title,
                points=rule.points,
                phrase=matched,
            )
        )
    total = sum(hit.points for hit in hits)
    return Score(
        score=total,
        blocked=total >= threshold,
        threshold=threshold,
        normalized=folded,
        hits=tuple(hits),
    )
