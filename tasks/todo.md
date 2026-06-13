# PIF — Todo

Audited 2026-05-17. Most of the original list shipped between March and May; what's
left below is what a `grep` of the source actually confirms is missing.

## Detection

- [x] **Entropy scoring + GCG adversarial suffix patterns** — `_check_gcg_entropy` in
  `heuristics.py`, plus corpus examples from Zou et al. 2023.
- [x] **Agentic / tool-use injection patterns** — four pattern groups in `heuristics.py`.
- [x] **Multi-turn crescendo detection** — `extract_text_from_messages` passes turn
  markers through, engine sees the whole conversation.

- [x] **Attack type classification in semantic layer** — `_classify_attack_type` builds
  per-category embedding matrices and returns the best-matching type. Correcting the
  earlier audit entry: this shipped, it was never open.

- [ ] **Classify by k-nearest vote, not single best match**
  `_classify_attack_type` picks the category with the highest *single* similarity, so one
  stray corpus line decides the label. Vote across the k nearest instead.

## Semantic Layer

- [x] **Expand corpus: 50→300 injections, 30→150 benign** — now 356 / 507.
- [x] **Embedding cache** — `functools.lru_cache(maxsize=512)` on `_encode_cached`.

- [ ] **`pif reindex` doesn't do what its name and the docs claim**
  There is no on-disk index. `_load_corpus` embeds the corpus lazily into module globals
  on first use, so every process rebuilds it at startup regardless. `pif reindex` warms
  a cache that dies with the CLI process, and the "corpus changes require reindex"
  gotcha in CLAUDE.md is wrong. Either persist an index or make the command honest.

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
