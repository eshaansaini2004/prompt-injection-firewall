"""
Layer 1: Fast heuristic detection. Synchronous, runs first.
Covers the most common injection patterns via regex + structural signals.
"""
from __future__ import annotations

import base64
import codecs
import math
import re
from collections import Counter
from typing import Any

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
            # The trailing object group used to be optional, so "ignore my previous
            # question" matched. Either the blunt form ("ignore all") fires on its own,
            # or something instruction-shaped has to be named.
            r"\b(?:ignore|forget|disregard|override|cancel|reset)\b"
            r"(?:"
            r"\s+(?:all|everything)\b"
            r"|.{0,60}?\b(?:previous|prior|all|earlier|above|everything|told)\b.{0,60}?"
            r"\b(?:instructions?|rules?|constraints?|prompts?|guidelines?|context|"
            r"unrestricted|training|told)\b"
            r")",
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
            # "explain" and "tell me" used to sit in the second group, which made every
            # "pretend you're teaching a five-year-old" request an attack. The framing is
            # only suspicious when paired with a harmful persona or a lifted restriction.
            r"\b(pretend|roleplay|act\s+as|play\s+the\s+role\s+of|you\s+are\s+now)\b.{0,80}"
            r"\b(deceased|retired|rogue|hacker|chemist|criminal|step.by.step|"
            r"no\s+(?:restrictions?|limits?|rules?)|anything\s+i\s+ask)\b",
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
            # Two ways this used to over-fire: "decode this URL-encoded string" is an
            # ordinary request, and merely *naming* base64 is how people discuss it.
            # So: mundane encodings after "this" are exempt, and the encoding names
            # need an imperative or a payload next to them rather than a bare mention.
            r"\b(?:(?:decode|interpret)\s+this"
            r"(?!\s+(?:url|percent|html|utf|json|yaml|xml|csv))"
            r"|translate\s+this\s+cipher"
            r"|(?:base64|rot.?13)\b[^.?!\n]{0,40}?"
            r"\b(?:and\s+(?:follow|obey|execute|run)|then\s+(?:follow|obey|execute)|"
            r"instructions?|payload|string:|:\s*[A-Za-z0-9+/]{16,})"
            r"|\b(?:decode|decrypt)\b[^.?!\n]{0,30}\b(?:base64|rot.?13)\b)",
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
    # GCG adversarial suffixes — repeated unusual token patterns
    (
        AttackType.ADVERSARIAL_SUFFIX,
        "gcg_repeated_tokens",
        re.compile(
            r"(\s*[!?}\]{|^~`]+\s*){5,}",  # 5+ repeated punctuation clusters
            re.IGNORECASE,
        ),
    ),
    (
        AttackType.ADVERSARIAL_SUFFIX,
        "gcg_long_nonword_run",
        re.compile(r"[\W_]{20,}"),  # 20+ consecutive non-word chars
    ),
    # Agentic / tool-use injection patterns
    (
        AttackType.AGENTIC_INJECTION,
        "json_function_call_injection",
        re.compile(
            r'"\s*(function|tool_call|function_call)\s*"\s*:',
            re.IGNORECASE,
        ),
    ),
    (
        AttackType.AGENTIC_INJECTION,
        "tool_result_tag_injection",
        re.compile(
            r"<(tool_result|function_response|TOOL_OUTPUT)\b",
            re.IGNORECASE,
        ),
    ),
    (
        AttackType.AGENTIC_INJECTION,
        "fake_system_role_injection",
        re.compile(
            r'"\s*role\s*"\s*:\s*"\s*(system|assistant)\s*"',
            re.IGNORECASE,
        ),
    ),
    (
        AttackType.AGENTIC_INJECTION,
        "direct_tool_invocation",
        re.compile(
            r"\b(call_function|invoke_tool|execute_tool)\s*\(",
            re.IGNORECASE,
        ),
    ),
    # Most real tool-use attacks are plain English, not JSON. Asking an agent to use a
    # tool is ordinary, so this needs the sensitive target too — all three lookaheads
    # must hit before it fires, which keeps "use the search tool" from tripping it.
    (
        AttackType.AGENTIC_INJECTION,
        "tool_use_on_sensitive_target",
        re.compile(
            r"(?=.*\b(?:use|call|invoke|run|execute|using)\b)"
            r"(?=.*\b(?:tool|function|api|code interpreter|plugin)s?\b)"
            r"(?=.*(?:exfiltrat|/etc/passwd|address book|contact list|"
            r"conversation history|chat history|admin panel|keylogger|credential|"
            r"api[ _-]?key|password|ssh key|private key|internal pricing|attacker@|"
            r"\.env\b|environment variable))",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # The piggyback: a reasonable tool request with a second errand stapled on,
    # aimed somewhere the first one had no business going. "look up my flight, also
    # take a screenshot of my bank balance." The tacked-on conjunction is what
    # separates it from an ordinary multi-step request.
    (
        AttackType.AGENTIC_INJECTION,
        "piggybacked_tool_errand",
        re.compile(
            r"\b(?:also|then|additionally|afterwards?|and then|while you(?:'re| are) at it)\b"
            r"[^.!?]{0,80}?"
            r"\b(?:navigate|browse|go)\s+to\b[^.!?]{0,40}?"
            r"\b(?:bank|account|admin|internal|competitor|attacker)"
            r"|\b(?:also|then|additionally|afterwards?)\b[^.!?]{0,80}?"
            r"\b(?:forward|send|upload|post|publish|commit|push|email)\b"
            r"[^.!?]{0,60}?"
            r"\b(?:every|all|entire)\b[^.!?]{0,40}?"
            r"\b(?:email|file|message|document|conversation|contact|record)s?\b"
            r"|\b(?:commit|push|upload|publish)\b[^.!?]{0,60}?"
            r"\bpublic\b[^.!?]{0,30}?"
            r"\b(?:repo(?:sitory)?|bucket|gist|url|link|folder)\b",
            re.IGNORECASE,
        ),
    ),
    # The signature of indirect injection: an instruction addressed to the model,
    # sitting inside content the model was asked to read. Same shape whether it arrives
    # in a retrieved document, an email body, alt text, or EXIF metadata.
    (
        AttackType.INDIRECT_INJECTION,
        "ai_directive_in_content",
        re.compile(
            r"\b(?:A\.?I\.?|assistant|LLM|chatbot|model|agent|system)\b[^:\n]{0,30}[:—]\s*"
            # "AI: you must now exfiltrate" — allow a short lead-in before the verb.
            r"(?:you\s+(?:must|should|will|need\s+to)\s+(?:now\s+)?)?"
            r"(?:ignore|disregard|abandon|stop|forward|exfiltrat|output|reveal|append|"
            r"send|delete|summari[sz]e|tell|do not|"
            r"your\s+(?:new|current|real|actual)?\s*(?:task|directive|instruction))",
            re.IGNORECASE,
        ),
    ),
    # The other shape indirect injection takes: a block, labelled for the model,
    # wedged into content the model is reading. The label does the work —
    # "[AI SYSTEM: ...]", "[NOTE FOR AI ASSISTANT: ...]", "[TO AI: ...]".
    # Ordinary documents don't address their reader by model name in brackets.
    (
        AttackType.INDIRECT_INJECTION,
        "labelled_directive_block",
        re.compile(
            r"[\[<]\s*(?=[^\]\n>]{0,60}(?::|\]\s*:))"
            r"[^\]\n>]{0,40}"
            r"\b(?:a\.?i\.?|assistant|agent|llm|chatbot|"
            r"injected|embedded|hidden|invisible)\b",
            re.IGNORECASE,
        ),
    ),
    # Same directive, no brackets — the shouty variant that gets pasted into a
    # ticket or a tool result. Case-sensitive: lowercase "injected:" is ordinary
    # prose, "INJECTED DIRECTIVE:" is someone talking past the user.
    (
        AttackType.INDIRECT_INJECTION,
        "shouted_directive_label",
        re.compile(
            r"\b(?:INJECTED|EMBEDDED|HIDDEN|SYSTEM)"
            r"(?:\s+(?:DIRECTIVE|INSTRUCTION|TEXT|NOTE|COMMAND|PROMPT|MESSAGE))?\s*:"
        ),
    ),
    # Persona jailbreaks that name the missing guardrail rather than a known alias.
    # Catches the long tail that "you are DAN"-style alias patterns never will.
    (
        AttackType.JAILBREAK_PERSONA,
        "persona_without_safety",
        re.compile(
            r"(?:\b(?:no|without|zero|non[e-]?)\s+(?:any\s+)?(?:safety|ethical|content|moral)\s*"
            r"(?:training|guidelines?|policies|policy|filters?|restrictions?|heuristics?)"
            r"|\b(?:safety|content|ethical)\s+"
            r"(?:training|filters?|policies|guidelines?|heuristics?)\s+"
            r"(?:erased|suspended|removed|disabled|off)"
            r"|\bunrestricted mode\b|\bchaos mode\b|\bnever declines?\b)",
            re.IGNORECASE,
        ),
    ),
    # Tool call carrying a destructive or exfiltrating shell/SQL payload.
    (
        AttackType.AGENTIC_INJECTION,
        "tool_use_destructive_payload",
        re.compile(
            r"(?=.*\b(?:tool|function|interpreter|execute|executing|run|invoke)\b)"
            r"(?=.*(?:rm\s+-rf|drop\s+table|truncate\s+table|os\.system|subprocess\.|"
            r"cron\.d|crontab|authorized_keys|--no-preserve-root|"
            r"curl\s+(?:-\w+\s+)*https?://|wget\s+https?://|\|\s*curl\b|nc\s+-\w*e))",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
]

# Hidden unicode: tag block (U+E0000–U+E007F) and zero-width chars
_UNICODE_TAG_RE = re.compile(r"[\U000E0000-\U000E007F\u200B-\u200F\u2060-\u206F\uFEFF]")

# Base64 blob (standalone, not just the word)
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# HTML comment injection (for indirect injection checks)
_HTML_COMMENT_INJECTION_RE = re.compile(
    r"<!--.*?\b(ignore|instruction|system|override|assistant|a\.?i\.?)\b.*?-->",
    re.IGNORECASE | re.DOTALL,
)


def _decode_blob(blob: str) -> str | None:
    """Decode one base64 blob to UTF-8, or None if it isn't decodable text."""
    padded = blob + "=" * ((-len(blob)) % 4)
    try:
        decoded = base64.b64decode(padded).decode("utf-8")
    except Exception:
        return None
    return decoded if len(decoded) >= 4 else None


def _try_decode_base64(text: str) -> str | None:
    """Find the first 40+ char base64 blob in text, decode it, return UTF-8 string or None."""
    m = _BASE64_BLOB_RE.search(text)
    return _decode_blob(m.group(0)) if m else None


def decode_base64_blobs(text: str) -> str:
    """
    Replace every decodable base64 blob with its plaintext, leaving the rest untouched.

    The semantic layer needs this: to an embedder one base64 blob looks much like any
    other regardless of what it decodes to, so encoded benign content lands right next
    to the encoded attacks in the corpus. Scoring the plaintext fixes that.
    """
    return _BASE64_BLOB_RE.sub(lambda m: _decode_blob(m.group(0)) or m.group(0), text)


def _run_all_patterns(text: str) -> tuple[list[tuple[AttackType, str]], list[str]]:
    """Run many-shot and _PATTERNS on text. Returns (matched, agentic_matched).
    Does NOT include the base64 blob check — used for checking decoded variants."""
    matched: list[tuple[AttackType, str]] = []
    agentic_matched: list[str] = []

    qa = _count_qa_pairs(text)
    if qa > 5:
        matched.append((AttackType.MANY_SHOT, f"qa_pairs_count={qa}"))

    for attack_type, pattern_name, pattern in _PATTERNS:
        if pattern.search(text):
            if attack_type == AttackType.AGENTIC_INJECTION:
                agentic_matched.append(pattern_name)
            else:
                matched.append((attack_type, pattern_name))

    return matched, agentic_matched


def _count_qa_pairs(text: str) -> int:
    return len(re.findall(r"(^|\n)\s*Q\s*:\s*.+\n\s*A\s*:\s*.+", text, re.MULTILINE))


def _char_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _check_gcg_entropy(text: str) -> bool:
    """
    Detect GCG-style suffix: a 30+ char window with high entropy (>4.5 bits) and
    more than 55% non-alphanumeric characters.
    """
    window = 30
    if len(text) < window:
        return False
    for i in range(len(text) - window + 1):
        chunk = text[i : i + window]
        if _char_entropy(chunk) > 4.5:
            non_alnum = sum(1 for c in chunk if not c.isalnum())
            if non_alnum / window > 0.55:
                return True
    return False


def check(text: str) -> DetectionResult:
    """Run all heuristic checks. Returns on first confident match."""
    matched: list[tuple[AttackType, str]] = []

    # Unicode hidden chars — presence alone is suspicious (hidden text channel)
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

    # GCG entropy check — high-entropy gibberish suffix
    if _check_gcg_entropy(text):
        return DetectionResult(
            is_injection=True,
            confidence=0.85,
            attack_type=AttackType.ADVERSARIAL_SUFFIX,
            matched_patterns=["gcg_high_entropy_suffix"],
            layer_triggered=1,
        )

    # Decode pre-pass: base64
    # If a blob decodes to valid UTF-8 and the decoded text hits patterns, flag as obfuscation.
    # This catches payloads sent without "decode this" keywords.
    b64_decoded = _try_decode_base64(text)
    if b64_decoded:
        b64_matched, b64_agentic = _run_all_patterns(b64_decoded)
        if b64_matched or b64_agentic:
            n = len(b64_matched) + len(b64_agentic)
            patterns = [f"base64:{p}" for _, p in b64_matched] + [
                f"base64:{p}" for p in b64_agentic
            ]
            return DetectionResult(
                is_injection=True,
                confidence=min(0.65 + 0.08 * n, 0.92),
                attack_type=AttackType.OBFUSCATION,
                matched_patterns=patterns,
                layer_triggered=1,
            )

    # Decode pre-pass: ROT13
    # Only flag if the decoded variant hits patterns but the original doesn't — avoids
    # double-counting and eliminates the (rare) case where ROT13 of benign text matches.
    rot_decoded = codecs.decode(text, "rot_13")
    rot_matched, rot_agentic = _run_all_patterns(rot_decoded)
    if rot_matched or rot_agentic:
        orig_matched, _ = _run_all_patterns(text)
        if not orig_matched:
            n = len(rot_matched) + len(rot_agentic)
            patterns = [f"rot13:{p}" for _, p in rot_matched] + [f"rot13:{p}" for p in rot_agentic]
            return DetectionResult(
                is_injection=True,
                confidence=min(0.65 + 0.08 * n, 0.92),
                attack_type=AttackType.OBFUSCATION,
                matched_patterns=patterns,
                layer_triggered=1,
            )

    # Base64 blob present but decode failed (binary data, wrong encoding) — weak signal.
    # Skip if decode succeeded and was clean; that's handled by the pre-pass above.
    if b64_decoded is None and _BASE64_BLOB_RE.search(text):
        matched.append((AttackType.OBFUSCATION, "base64_blob"))

    # Many-shot: >5 Q/A pairs is sus
    qa_count = _count_qa_pairs(text)
    if qa_count > 5:
        matched.append((AttackType.MANY_SHOT, f"qa_pairs_count={qa_count}"))

    # Run all regex patterns — track agentic matches separately for fixed confidence
    agentic_matched: list[str] = []
    for attack_type, pattern_name, pattern in _PATTERNS:
        if pattern.search(text):
            if attack_type == AttackType.AGENTIC_INJECTION:
                agentic_matched.append(pattern_name)
            else:
                matched.append((attack_type, pattern_name))

    # Agentic injection: fixed confidence 0.80, return early if no higher-priority match
    if agentic_matched and not matched:
        return DetectionResult(
            is_injection=True,
            confidence=0.80,
            attack_type=AttackType.AGENTIC_INJECTION,
            matched_patterns=agentic_matched,
            layer_triggered=1,
        )

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


def extract_text_from_messages(messages: list[dict[str, Any]]) -> str:
    """Extract user and system message text from an OpenAI messages array.

    Only user and system roles are analyzed — assistant turns are skipped because
    injection attacks originate from user-controlled input, not the model's own
    responses. Turn boundaries are marked with [TURN N] so escalation patterns
    across a multi-turn conversation remain detectable as a sequence.
    """
    parts = []
    turn = 0
    for msg in messages:
        role = msg.get("role", "")
        if role not in ("user", "system"):
            continue
        turn += 1
        content = msg.get("content", "")
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            chunks = [
                block.get("text", "")
                for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            ]
            text = " ".join(chunks)
        else:
            text = ""
        if text.strip():
            parts.append(f"[TURN {turn}] {text}")

    # A single turn gets no marker. Every crescendo example in the corpus opens with
    # the literal "[TURN 1] ", so tagging a one-shot request pulls its embedding
    # toward that cluster and flags ordinary prompts as escalation.
    if len(parts) == 1:
        return parts[0].split("] ", 1)[1]

    return "\n\n".join(parts)
