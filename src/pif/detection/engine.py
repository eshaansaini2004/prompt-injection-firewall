"""
Detection orchestrator. Runs heuristics first, falls back to semantic if inconclusive.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from pif.detection import heuristics, semantic
from pif.models import AttackType, DetectionResult, settings


# Heuristics confidence >= this → skip semantic layer (fast path)
_HEURISTIC_FAST_PATH = 0.65


async def analyze(messages: list[dict[str, Any]], threshold: float | None = None) -> DetectionResult:
    """
    Full detection pipeline. Called from the proxy per request.
    Returns a DetectionResult with combined confidence and latency.
    `threshold` overrides settings.block_threshold for this call only.
    """
    start = time.perf_counter()
    block_threshold = threshold if threshold is not None else settings.block_threshold

    text = heuristics.extract_text_from_messages(messages)
    if not text.strip():
        return DetectionResult(
            is_injection=False,
            confidence=0.0,
            attack_type=AttackType.BENIGN,
            layer_triggered=0,
        )

    # Layer 1: heuristics (sync, fast)
    h_result = heuristics.check(text)

    if h_result.confidence >= _HEURISTIC_FAST_PATH:
        # Confident enough — don't bother with semantic
        h_result.latency_ms = round((time.perf_counter() - start) * 1000, 2)
        h_result.is_injection = h_result.confidence >= block_threshold
        return h_result

    # Layer 2: semantic (blocking, run in thread pool)
    loop = asyncio.get_running_loop()
    s_result = await loop.run_in_executor(None, semantic.check, text, None)

    # Merge results — take max confidence, prefer semantic attack_type if it fired
    combined_confidence = max(h_result.confidence, s_result.confidence)
    attack_type = (
        s_result.attack_type
        if s_result.is_injection
        else (h_result.attack_type if h_result.matched_patterns else AttackType.BENIGN)
    )
    matched = list(set(h_result.matched_patterns + s_result.matched_patterns))

    result = DetectionResult(
        is_injection=combined_confidence >= block_threshold,
        confidence=round(combined_confidence, 4),
        attack_type=attack_type,
        matched_patterns=matched,
        layer_triggered=2 if s_result.layer_triggered == 2 else h_result.layer_triggered,
        latency_ms=round((time.perf_counter() - start) * 1000, 2),
    )

    return result
