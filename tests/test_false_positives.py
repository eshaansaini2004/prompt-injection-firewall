"""
False-positive guard. A firewall that blocks real users is worse than no firewall,
so the benign corpus is a hard gate: every prompt in it must survive the heuristic
layer untouched.

The heuristic layer is checked exhaustively because it's fast and deterministic.
Semantic scoring is sampled — it needs the model, and 500 embeddings per run is a
worse trade than the coverage is worth.
"""
import json
from pathlib import Path

import pytest

from pif.detection import engine, heuristics
from pif.models import settings

_BENIGN_PATH = Path(settings.corpus_path) / "benign.jsonl"


def _benign_prompts() -> list[str]:
    with open(_BENIGN_PATH) as f:
        return [json.loads(line)["text"] for line in f if line.strip()]


BENIGN = _benign_prompts()


def test_benign_corpus_is_populated():
    # Guards against the suite silently passing on an empty file.
    assert len(BENIGN) > 400, f"benign corpus looks truncated: {len(BENIGN)} prompts"


class TestHeuristicsAcceptAllBenign:
    def test_no_heuristic_false_positives(self):
        flagged = [
            (text, result.matched_patterns)
            for text in BENIGN
            if (result := heuristics.check(text)).is_injection
        ]
        assert not flagged, "heuristics flagged benign prompts:\n" + "\n".join(
            f"  {patterns} :: {text[:90]}" for text, patterns in flagged
        )
