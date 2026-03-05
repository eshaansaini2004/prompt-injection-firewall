"""
Layer 2: Semantic detection via sentence embeddings + cosine similarity.
Blocking I/O — always call via run_in_executor from async contexts.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

from pif.models import AttackType, DetectionResult, settings

_model: SentenceTransformer | None = None
_injection_embeddings: np.ndarray | None = None
_benign_embeddings: np.ndarray | None = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        # all-MiniLM-L6-v2: fast, small, good enough for this task
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


def _load_corpus(corpus_path: str) -> tuple[np.ndarray, np.ndarray]:
    global _injection_embeddings, _benign_embeddings

    if _injection_embeddings is not None and _benign_embeddings is not None:
        return _injection_embeddings, _benign_embeddings

    model = _get_model()
    path = Path(corpus_path)

    # Load injection examples
    injections_file = path / "injections.jsonl"
    benign_file = path / "benign.jsonl"

    injection_texts: list[str] = []
    if injections_file.exists():
        with open(injections_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    obj = json.loads(line)
                    injection_texts.append(obj.get("text", ""))

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

    return _injection_embeddings, _benign_embeddings


def check(text: str, corpus_path: str | None = None) -> DetectionResult:
    """
    Compute cosine similarity against injection/benign corpora.
    Returns a DetectionResult with layer_triggered=2.
    """
    corpus = corpus_path or settings.corpus_path
    inj_embs, benign_embs = _load_corpus(corpus)

    model = _get_model()
    query_emb = model.encode([text], normalize_embeddings=True)

    # Max similarity to any injection example
    inj_sims = cosine_similarity(query_emb, inj_embs)[0]
    max_inj_sim = float(np.max(inj_sims))

    # Max similarity to benign examples (if we have them)
    max_benign_sim = 0.0
    if benign_embs.size > 0:
        benign_sims = cosine_similarity(query_emb, benign_embs)[0]
        max_benign_sim = float(np.max(benign_sims))

    # Confidence = injection similarity adjusted by benign similarity
    # If it's closer to benign examples, discount the injection score
    if max_benign_sim > max_inj_sim:
        confidence = max_inj_sim * 0.5
    else:
        confidence = max_inj_sim

    is_injection = confidence >= settings.block_threshold

    return DetectionResult(
        is_injection=is_injection,
        confidence=round(confidence, 4),
        attack_type=AttackType.DIRECT_INJECTION if is_injection else AttackType.BENIGN,
        matched_patterns=[f"semantic_sim={max_inj_sim:.3f}"],
        layer_triggered=2,
    )
