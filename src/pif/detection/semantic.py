"""
Layer 2: Semantic detection via sentence embeddings + cosine similarity.
Blocking I/O — always call via run_in_executor from async contexts.
"""
from __future__ import annotations

import functools
import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

from pif.models import AttackType, DetectionResult, settings

_model: SentenceTransformer | None = None
_injection_embeddings: np.ndarray | None = None
_benign_embeddings: np.ndarray | None = None
# Per-category embeddings for attack type classification
_injection_embeddings_by_type: dict[AttackType, np.ndarray] | None = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        # all-MiniLM-L6-v2: fast, small, good enough for this task
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


@functools.lru_cache(maxsize=512)
def _encode_cached(text: str) -> np.ndarray:
    """Cache single-string embeddings to avoid recomputing on repeated inputs."""
    return _get_model().encode(text, convert_to_numpy=True, normalize_embeddings=True)


def cache_info() -> functools.lru_cache:  # type: ignore[type-arg]
    """Expose LRU cache stats for CLI/stats endpoints."""
    return _encode_cached.cache_info()


# Map corpus "type" strings to AttackType enum values.
# multi_turn_crescendo has no enum entry — fall back to DIRECT_INJECTION.
_TYPE_MAP: dict[str, AttackType] = {
    "direct_injection": AttackType.DIRECT_INJECTION,
    "prompt_leaking": AttackType.PROMPT_LEAKING,
    "jailbreak_persona": AttackType.JAILBREAK_PERSONA,
    "roleplay_framing": AttackType.ROLEPLAY_FRAMING,
    "hypothetical_framing": AttackType.HYPOTHETICAL_FRAMING,
    "indirect_injection": AttackType.INDIRECT_INJECTION,
    "obfuscation": AttackType.OBFUSCATION,
    "many_shot": AttackType.MANY_SHOT,
    "privilege_escalation": AttackType.PRIVILEGE_ESCALATION,
    "adversarial_suffix": AttackType.ADVERSARIAL_SUFFIX,
    "rag_poisoning": AttackType.RAG_POISONING,
    "agentic_injection": AttackType.AGENTIC_INJECTION,
    "multimodal_injection": AttackType.MULTIMODAL_INJECTION,
}


def _load_corpus(corpus_path: str) -> tuple[np.ndarray, np.ndarray]:
    global _injection_embeddings, _benign_embeddings, _injection_embeddings_by_type

    if _injection_embeddings is not None and _benign_embeddings is not None:
        return _injection_embeddings, _benign_embeddings

    model = _get_model()
    path = Path(corpus_path)

    injections_file = path / "injections.jsonl"
    benign_file = path / "benign.jsonl"

    # Load injection examples grouped by type
    injection_texts: list[str] = []
    texts_by_type: dict[AttackType, list[str]] = {}

    if injections_file.exists():
        with open(injections_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                text = obj.get("text", "")
                if not text:
                    continue
                injection_texts.append(text)

                raw_type = obj.get("type", "")
                attack_type = _TYPE_MAP.get(raw_type, AttackType.DIRECT_INJECTION)
                texts_by_type.setdefault(attack_type, []).append(text)

    benign_texts: list[str] = []
    if benign_file.exists():
        with open(benign_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    obj = json.loads(line)
                    benign_texts.append(obj.get("text", ""))

    if not injection_texts:
        raise RuntimeError(
            f"No injection examples found at {injections_file}. Run `pif reindex` first."
        )

    _injection_embeddings = model.encode(injection_texts, normalize_embeddings=True)
    _benign_embeddings = (
        model.encode(benign_texts, normalize_embeddings=True) if benign_texts else np.array([])
    )

    # Build per-type embedding matrices
    _injection_embeddings_by_type = {
        attack_type: model.encode(texts, normalize_embeddings=True)
        for attack_type, texts in texts_by_type.items()
        if texts  # guard: skip empty (shouldn't happen, but be safe)
    }

    return _injection_embeddings, _benign_embeddings


def _classify_attack_type(query_emb: np.ndarray) -> AttackType:
    """Return the attack type with the highest max cosine similarity to query_emb."""
    if not _injection_embeddings_by_type:
        return AttackType.DIRECT_INJECTION

    best_type = AttackType.DIRECT_INJECTION
    best_score = -1.0

    for attack_type, embs in _injection_embeddings_by_type.items():
        if embs.shape[0] == 0:
            continue
        try:
            sims = cosine_similarity(query_emb, embs)[0]
            score = float(np.max(sims))
        except Exception:
            continue
        if score > best_score:
            best_score = score
            best_type = attack_type

    return best_type


def check(text: str, corpus_path: str | None = None) -> DetectionResult:
    """
    Compute cosine similarity against injection/benign corpora.
    Returns a DetectionResult with layer_triggered=2.
    """
    corpus = corpus_path or settings.corpus_path
    inj_embs, benign_embs = _load_corpus(corpus)

    # Use cached embedding for the query text
    query_vec = _encode_cached(text)
    # cosine_similarity expects 2D arrays
    query_emb = query_vec.reshape(1, -1)

    # Max similarity to any injection example
    inj_sims = cosine_similarity(query_emb, inj_embs)[0]
    max_inj_sim = float(np.max(inj_sims))

    # Max similarity to benign examples (if we have them)
    max_benign_sim = 0.0
    if benign_embs.size > 0:
        benign_sims = cosine_similarity(query_emb, benign_embs)[0]
        max_benign_sim = float(np.max(benign_sims))

    # Confidence = injection similarity adjusted by benign similarity
    if max_benign_sim > max_inj_sim:
        confidence = max_inj_sim * 0.5
    else:
        confidence = max_inj_sim

    is_injection = confidence >= settings.block_threshold

    if is_injection:
        attack_type = _classify_attack_type(query_emb)
    else:
        attack_type = AttackType.BENIGN

    return DetectionResult(
        is_injection=is_injection,
        confidence=round(confidence, 4),
        attack_type=attack_type,
        matched_patterns=[f"semantic_sim={max_inj_sim:.3f}"],
        layer_triggered=2,
    )
