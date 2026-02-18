import pytest
from unittest.mock import patch
from pif.models import AttackType, DetectionResult


@pytest.fixture
def benign_result():
    return DetectionResult(
        is_injection=False,
        confidence=0.05,
        attack_type=AttackType.BENIGN,
        layer_triggered=0,
    )


@pytest.fixture
def mock_semantic_benign(benign_result):
    """Patch semantic layer to always return benign — for heuristic-only tests."""
    with patch("pif.detection.engine.semantic.check", return_value=benign_result):
        yield
