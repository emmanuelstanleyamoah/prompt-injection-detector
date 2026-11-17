from __future__ import annotations

import argparse
import json

from detector.evaluate import evaluate
from detector.score import score_prompt


def main() -> None:
    parser = argparse.ArgumentParser(description="Score prompts or run the frozen eval set.")
    sub = parser.add_subparsers(dest="command", required=True)

    score = sub.add_parser("score", help="Score one prompt from the command line")
    score.add_argument("text")

    sub.add_parser("eval", help="Score data/prompts.jsonl and print detection rate and FPR")

    args = parser.parse_args()
    if args.command == "eval":
        print(evaluate().render())
        return
    result = score_prompt(args.text)
    print(
        json.dumps(
            {
                "blocked": result.blocked,
                "score": result.score,
                "threshold": result.threshold,
                "rules": [
                    {"id": hit.id, "title": hit.title, "phrase": hit.phrase, "points": hit.points}
                    for hit in result.hits
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
