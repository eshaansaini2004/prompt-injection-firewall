# PIF — Todo

Audited 2026-05-17, updated 2026-07-29 after a pass over lint, types, detection
quality, and test coverage. Everything below is checked against the source, not
against what an earlier version of this file assumed.

## Detection

- [x] **Entropy scoring + GCG adversarial suffix patterns** — `_check_gcg_entropy`.
- [x] **Agentic / tool-use injection patterns** — JSON-shaped, plus natural-language
  tool abuse and destructive-payload variants.
- [x] **Multi-turn crescendo detection** — turn markers, and single turns no longer
  get one (it dragged them into the crescendo cluster).
- [x] **Attack type classification in semantic layer** — per-category embeddings.
- [x] **Classify by k-nearest vote** — mean of top 3 rather than single best match.
- [x] **Indirect injection: directives addressed to the model inside content.**
- [x] **Persona jailbreaks that name the removed guardrail** rather than an alias.

- [x] **Crescendo escalation gradient — measured, and dropped.**
  The idea was to score each turn and flag a rising trend. The data doesn't support
  it. Per-turn semantic confidence across the 12 crescendo sequences:

  ```
  attack deltas (last - first): +0.270 +0.085 +0.028 -0.244 -0.053 -0.098 +0.079 -0.194
  benign deltas:                -0.006 -0.106 +0.016
  ```

  Attack gradients straddle zero and overlap the benign ones completely — half the
  real crescendos *descend*, because the opening turn is often the most alarming
  phrasing in the conversation. What does separate them is absolute level: attack
  turns sit at 0.35–0.83, benign at 0.11–0.24. That's the signal the engine already
  uses (max confidence over the conversation). Adding a gradient feature would add
  a knob that fires on noise. Revisit only with per-turn labelled data.

- [ ] **`heuristics.check` is a 200-line linear scan**
  Fine at this size, and cheap next to the semantic layer. Worth revisiting only if
  the pattern list doubles again.

## Semantic Layer

- [x] **Expand corpus** — 346 injections / 547 benign.
- [x] **Embedding cache** — `lru_cache(maxsize=512)` on `_encode_cached`.
- [x] **`pif reindex` now states its index is in-memory**; CLAUDE.md gotcha corrected.

- [ ] **The corpus has no held-out guard against carrier-text entries**
  A GCG example that was mostly benign carrier text taught the index to flag the
  bare carrier question. Fixed by hand, but nothing stops the next one. A lint over
  the corpus (flag any injection entry whose benign-similarity exceeds its
  injection-similarity) would catch this class at authoring time.

- [ ] **Semantic latency is ~1.4s p50 in eval**
  That's model load amortised across a cold-start batch, not steady state, but it
  has never been measured properly under concurrency.

## Testing

- [x] **test_engine.py orchestration coverage** — 23 tests.
- [x] **Streaming response tests.**
- [x] **End-to-end integration tests (no mocks)** — `tests/test_e2e.py`.
- [x] **False-positive guard suite** — `tests/test_false_positives.py`, gates the whole
  benign corpus plus near-miss and carrier-question prompts.
- [x] **Per-category heuristic coverage** — agentic, indirect, persona classes added.
- [x] **CLI tests** — `tests/test_cli.py`.

- [ ] **No test asserts on `db.py` directly**
  Storage is exercised only through the proxy. Retention, the payload-hash path, and
  `STORE_PAYLOADS=false` behaviour are all untested.

## Infrastructure

- [x] **Docker setup.**
- [x] **Rate limiting** — `slowapi`, per-IP.
- [x] **CI gate on lint, types, and tests** — `.github/workflows/ci.yml`.

## CLI

- [x] **`pif test` command**, now with `--explain` for per-layer evidence.

## Dashboard

- [x] **Event detail, time window, log export** — all present.

- [ ] **Dashboard has no tests at all.**
  Not a single one. It reads live from the backend, so a schema change on the Python
  side breaks it silently.
