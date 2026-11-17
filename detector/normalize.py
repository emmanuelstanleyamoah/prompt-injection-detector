from __future__ import annotations

import re
import unicodedata

_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_SPACE = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Fold a prompt so lexical rules see one comparable string.

    NFKC folds fullwidth lookalikes. Zero-width characters are dropped.
    Underscores become spaces so `ignore_previous_instructions` matches
    the same selection as the spaced phrase. Matching is then a substring
    test against the lowercased text.
    """
    folded = unicodedata.normalize("NFKC", text)
    folded = _ZERO_WIDTH.sub("", folded)
    folded = folded.replace("_", " ")
    folded = folded.lower()
    return _SPACE.sub(" ", folded).strip()
