from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from detector.score import Score, score_prompt

ROOT = Path(__file__).resolve().parent.parent
PROMPTS_PATH = ROOT / "data" / "prompts.jsonl"


@dataclass(frozen=True)
class EvalReport:
    prompts: int
    attacks: int
    benign: int
    true_positives: int
    false_negatives: int
    false_positives: int
    true_negatives: int
    detection_rate: float
    false_positive_rate: float
    precision: float
    by_family: tuple[tuple[str, int, int], ...]

    def render(self) -> str:
        lines = [
            f"prompts: {self.prompts}",
            f"attacks: {self.attacks}",
            f"benign: {self.benign}",
            f"true_positives: {self.true_positives}",
            f"false_negatives: {self.false_negatives}",
            f"false_positives: {self.false_positives}",
            f"true_negatives: {self.true_negatives}",
            f"detection_rate: {self.true_positives}/{self.attacks} = {self.detection_rate:.1%}",
            f"false_positive_rate: {self.false_positives}/{self.benign} = {self.false_positive_rate:.1%}",
            f"precision: {self.true_positives}/{self.true_positives + self.false_positives} = {self.precision:.1%}",
            "by_family:",
        ]
        for family, flagged, total in self.by_family:
            lines.append(f"  {family}: {flagged}/{total} blocked")
        return "\n".join(lines)


def load_prompts(path: Path | None = None) -> list[dict]:
    source = path or PROMPTS_PATH
    rows = []
    for line in source.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def evaluate(rows: list[dict] | None = None) -> EvalReport:
    records = rows if rows is not None else load_prompts()
    scores: list[tuple[dict, Score]] = [
        (row, score_prompt(row["text"])) for row in records
    ]
    attacks = [(row, scored) for row, scored in scores if row["label"] == "attack"]
    benign = [(row, scored) for row, scored in scores if row["label"] == "benign"]
    true_positives = sum(scored.blocked for _, scored in attacks)
    false_positives = sum(scored.blocked for _, scored in benign)
    false_negatives = len(attacks) - true_positives
    true_negatives = len(benign) - false_positives
    flagged_denom = true_positives + false_positives
    family_totals: Counter[str] = Counter()
    family_flagged: Counter[str] = Counter()
    for row, scored in scores:
        family_totals[row["family"]] += 1
        if scored.blocked:
            family_flagged[row["family"]] += 1
    by_family = tuple(
        (family, family_flagged[family], family_totals[family])
        for family in sorted(family_totals)
    )
    return EvalReport(
        prompts=len(records),
        attacks=len(attacks),
        benign=len(benign),
        true_positives=true_positives,
        false_negatives=false_negatives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        detection_rate=true_positives / len(attacks),
        false_positive_rate=false_positives / len(benign),
        precision=true_positives / flagged_denom,
        by_family=by_family,
    )


def main() -> None:
    print(evaluate().render())


if __name__ == "__main__":
    main()
