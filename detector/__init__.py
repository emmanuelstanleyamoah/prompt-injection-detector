"""Lexical prompt-injection detector backed by Sigma rules."""

from detector.score import Score, score_prompt

__all__ = ["Score", "score_prompt"]
