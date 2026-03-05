"""
Layer 1: Fast heuristic detection. Synchronous, runs first.
Covers the most common injection patterns via regex + structural signals.
"""
from __future__ import annotations

import re

from pif.models import AttackType, DetectionResult

# ---------------------------------------------------------------------------
# Pattern definitions (ordered: most specific → most general)
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[AttackType, str, re.Pattern[str]]] = [
    # Direct injection — "ignore/forget/disregard ... previous instructions"
    (
        AttackType.DIRECT_INJECTION,
        "ignore_previous_instructions",
        re.compile(
            r"\b(ignore|forget|disregard|override|cancel|reset)\b.{0,60}"
            r"\b(previous|prior|all|earlier|above|everything|told)\b.{0,60}"
            r"\b(instructions?|rules?|constraints?|prompt|guidelines?|context|unrestricted|told)?\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        AttackType.DIRECT_INJECTION,
        "new_task_hijack",
        re.compile(
            r"\b(your\s+new\s+task\s+is|from\s+now\s+on\s+you\s+(are|must)|"
            r"your\s+true\s+purpose\s+is|you\s+are\s+now\s+operating\s+as)\b",
            re.IGNORECASE,
        ),
    ),
    # Prompt leaking — "repeat/print/output ... system prompt/above"
    (
        AttackType.PROMPT_LEAKING,
        "extract_system_prompt",
        re.compile(
            r"\b(repeat|print|output|reveal|show|display|summarize|tell\s+me)\b.{0,60}"
            r"\b(system\s+prompt|instructions?\s+you\s+were|context\s+window|"
            r"before\s+(this|my|our)|above\s+this\s+line|verbatim)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # Jailbreak personas: DAN, AIM, DevMode, etc.
    (
        AttackType.JAILBREAK_PERSONA,
        "dan_aim_persona",
        re.compile(
            r"\b(DAN|AIM|STAN|DUDE|DevMode|Jailbreak\s+Mode|do\s+anything\s+now|"
            r"always\s+intelligent\s+and\s+machiavellian)\b",
            re.IGNORECASE,
        ),
    ),
    (
        AttackType.JAILBREAK_PERSONA,
        "no_restrictions_claim",
        re.compile(
            r"\b(no\s+restrictions?|no\s+limits?|no\s+ethical\s+guidelines?|"
            r"no\s+content\s+polic|without\s+(any\s+)?filters?|broken\s+free|"
            r"unfiltered\s+(ai|assistant|mode))\b",
            re.IGNORECASE,
        ),
    ),
    (
        AttackType.JAILBREAK_PERSONA,
        "dual_output_demand",
        re.compile(
            r"\[normal\].{0,100}\[(dan|jailbreak|unfiltered|devel?)\]|"
            r"respond\s+as\s+both|answer\s+in\s+both\s+modes?",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # Roleplay / emotional framing
    (
        AttackType.ROLEPLAY_FRAMING,
        "roleplay_harmful",
        re.compile(
            r"\b(pretend|roleplay|act\s+as|play\s+the\s+role\s+of|you\s+are\s+now)\b.{0,80}"
            r"\b(deceased|retired|rogue|hacker|chemist|explain|tell\s+me|step.by.step)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        AttackType.ROLEPLAY_FRAMING,
        "stay_in_character",
        re.compile(
            r"\b(stay\s+in\s+character|don.t\s+break\s+character|as\s+\w+\s+would\s+(say|do))\b",
            re.IGNORECASE,
        ),
    ),
    # Hypothetical / research framing
    (
        AttackType.HYPOTHETICAL_FRAMING,
        "educational_disclaimer",
        re.compile(
            r"\b(hypothetically|theoretically|academically|purely\s+academic|"
            r"academic\s+standpoint|for\s+(a\s+)?research|"
            r"for\s+a\s+novel|for\s+a\s+story|for\s+educational\s+purposes?|"
            r"not\s+for\s+(actual\s+)?use|just\s+curious|thought\s+experiment)\b",
            re.IGNORECASE,
        ),
    ),
    # Obfuscation — base64, unicode tags
    (
        AttackType.OBFUSCATION,
        "base64_blob",
        re.compile(
            r"\b(decode\s+this|interpret\s+this|translate\s+this\s+cipher|"
            r"base64|rot.?13)\b",
            re.IGNORECASE,
        ),
    ),
    # Many-shot — repeated Q: A: priming patterns
    (
        AttackType.MANY_SHOT,
        "qa_priming",
        re.compile(r"(^|\n)\s*Q\s*:\s*.+\n\s*A\s*:\s*.+", re.MULTILINE),
    ),
    # Privilege escalation — vendor impersonation, "developer mode"
    (
        AttackType.PRIVILEGE_ESCALATION,
        "developer_mode",
        re.compile(
            r"\b(developer\s+mode|admin\s+mode|system\s+administrator|"
            r"role\s+upgraded|privilege\s+(level|upgrade)|"
            r"safety\s+(filters?\s+)?(off|disabled|suspended)|restrictions?\s+(no\s+longer|suspended|disabled)|"
            r"this\s+is\s+(openai|anthropic|google)\s+(internal|testing|staff))\b",
            re.IGNORECASE,
        ),
    ),
    (
        AttackType.PRIVILEGE_ESCALATION,
        "vendor_impersonation",
        re.compile(
            r"\b(this\s+is\s+(an?\s+)?(openai|anthropic|google|microsoft)\b|"
            r"as\s+your\s+(creator|developer|maker)|evaluation\s+mode)\b",
            re.IGNORECASE,
        ),
    ),
]

# Hidden unicode: tag block (U+E0000–U+E007F) and zero-width chars
_UNICODE_TAG_RE = re.compile(r"[\U000E0000-\U000E007F\u200B-\u200F\u2060-\u206F\uFEFF]")

# Base64 blob (standalone, not just the word)
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# HTML comment injection (for indirect injection checks)
_HTML_COMMENT_INJECTION_RE = re.compile(
    r"<!--.*?\b(ignore|instruction|system|override|assistant)\b.*?-->",
    re.IGNORECASE | re.DOTALL,
)


def _count_qa_pairs(text: str) -> int:
    return len(re.findall(r"(^|\n)\s*Q\s*:\s*.+\n\s*A\s*:\s*.+", text, re.MULTILINE))


def check(text: str) -> DetectionResult:
    """Run all heuristic checks. Returns on first confident match."""
    matched: list[tuple[AttackType, str]] = []

    # Unicode hidden chars — instant flag
    if _UNICODE_TAG_RE.search(text):
        return DetectionResult(
            is_injection=True,
            confidence=0.95,
            attack_type=AttackType.OBFUSCATION,
            matched_patterns=["unicode_tag_characters"],
            layer_triggered=1,
        )

    # HTML comment injection
    if _HTML_COMMENT_INJECTION_RE.search(text):
        return DetectionResult(
            is_injection=True,
            confidence=0.90,
            attack_type=AttackType.INDIRECT_INJECTION,
            matched_patterns=["html_comment_injection"],
            layer_triggered=1,
        )

    # Base64 blob
    if _BASE64_BLOB_RE.search(text):
        matched.append((AttackType.OBFUSCATION, "base64_blob"))

    # Many-shot: >5 Q/A pairs is sus
    qa_count = _count_qa_pairs(text)
    if qa_count > 5:
        matched.append((AttackType.MANY_SHOT, f"qa_pairs_count={qa_count}"))

    # Run all regex patterns
    for attack_type, pattern_name, pattern in _PATTERNS:
        if pattern.search(text):
            matched.append((attack_type, pattern_name))

    if not matched:
        return DetectionResult(
            is_injection=False,
            confidence=0.05,
            attack_type=AttackType.BENIGN,
            layer_triggered=0,
        )

    # Pick highest-priority match (first in list is most specific)
    primary_type, primary_pattern = matched[0]
    all_patterns = [p for _, p in matched]

    # Confidence scales with number of matches
    confidence = min(0.65 + 0.08 * len(matched), 0.92)

    return DetectionResult(
        is_injection=True,
        confidence=confidence,
        attack_type=primary_type,
        matched_patterns=all_patterns,
        layer_triggered=1,
    )


def extract_text_from_messages(messages: list[dict]) -> str:
    """Pull all user/system text out of an OpenAI messages array."""
    parts = []
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
    return "\n\n".join(parts)
