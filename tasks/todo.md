# PIF — Todo

Audited 2026-05-17. Most of the original list shipped between March and May; what's
left below is what a `grep` of the source actually confirms is missing.

## Detection

- [x] **Entropy scoring + GCG adversarial suffix patterns** — `_check_gcg_entropy` in
  `heuristics.py`, plus corpus examples from Zou et al. 2023.
- [x] **Agentic / tool-use injection patterns** — four pattern groups in `heuristics.py`.
- [x] **Multi-turn crescendo detection** — `extract_text_from_messages` passes turn
  markers through, engine sees the whole conversation.

- [ ] **Attack type classification in semantic layer**
  Semantic hits still always return `DIRECT_INJECTION`. The corpus records carry a
  `type` field that the index throws away. Keep it, vote over the k nearest.

## Semantic Layer

- [x] **Expand corpus: 50→300 injections, 30→150 benign** — now 356 / 507.
- [x] **Embedding cache** — `functools.lru_cache(maxsize=512)` on `_encode_cached`.

- [ ] **Index staleness warning**
  Reindex is manual and silent. If a corpus file is newer than the built index, say so
  at startup instead of scoring against a stale one.

## Testing

- [x] **test_engine.py — orchestration coverage** — 23 tests.
- [x] **Streaming response tests** — three in `test_proxy.py` covering SSE passthrough,
  pre-upstream block, and upstream error.

- [ ] **End-to-end integration tests (no mocks)**
  Everything currently stubs the detection result. Nothing runs both layers together
  and asserts on the real block/pass decision.

- [ ] **Per-category heuristic coverage**
  `test_heuristics.py` is heavy on direct injection and obfuscation, thin on the other
  ten categories. Recall regressions there would go unnoticed.

- [ ] **False-positive guard suite**
  The benign corpus is large but untested as a suite. Near-miss prompts (security
  questions, prompt-engineering discussion) are the ones that will break precision.

## Infrastructure

- [x] **Docker setup** — `Dockerfile` + `docker-compose.yml`.
- [x] **Rate limiting** — `slowapi`, per-IP, `settings.rate_limit`.

- [ ] **CI gate on lint, types, and tests**
  `.github/workflows/eval.yml` runs the eval and nothing else. `ruff` and `mypy` both
  fail on `master` right now and CI is happy about it.

## CLI

- [x] **`pif test` command** — takes a prompt, prints confidence and attack type.

- [ ] **`pif test` should show which patterns matched per layer**
  Right now it prints the verdict without the evidence, which makes corpus debugging
  guesswork.

## Dashboard

- [x] **Event detail / payload inspection** — `EventDetailPanel.tsx`.
- [x] **Configurable time window on chart** — 1h / 6h / 24h / 7d.
- [x] **Log export** — CSV/JSON download.
