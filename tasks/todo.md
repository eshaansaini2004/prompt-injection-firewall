# PIF — Todo

Audited 2026-05-17, updated 2026-08-31 after two weeks on false positives, the
corpus lint, agentic/indirect recall, and the proxy's front door. Everything below
is checked against the source, not against what an earlier version of this file
assumed.

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

- [x] **Carrier-text corpus lint** — `pif check-corpus --semantic-lint`. Flags any
  injection entry whose nearest benign neighbour beats its nearest attack neighbour.
  Currently reports 10 entries, including the one found by hand.

- [x] **Act on the carrier-text entries the lint reports.** Done, and the lint
  itself was wrong. Nearest-benign-neighbour flagged healthy entries and missed the
  harmful ones; it's now leave-one-out (an entry is flagged only when dropping it
  takes its own opening sentence below threshold *and* leaves it reading benign).
  That surfaced the real damage: a resume header blocked at 0.64, a support ticket
  at 0.66, a product listing at 0.71 — ordinary RAG content that indirect-injection
  entries had taught the index to flag. Fixed with 41 benign prompts across GCG
  carriers, tool-use, and retrieved-document shapes.

- [ ] **17 entries still on the lint list.** They no longer cause false positives
  (the benign neighbours pull them back), so this is corpus hygiene, not a bug.

- [x] **Semantic latency measured under concurrency** — `scripts/bench_semantic.py`.
  Steady state is 5ms p50, not 1.4s (that was model load spread over a cold-start
  batch). Throughput is 124-190 req/s at *every* concurrency level and p50 scales
  linearly with it, so the thread pool buys nothing — the embedding work serializes
  on the GIL and torch's intra-op threads. `run_in_executor` still earns its keep by
  keeping the event loop free; it is not a scaling story. Table in the README.

## Testing

- [x] **test_engine.py orchestration coverage** — 23 tests.
- [x] **Streaming response tests.**
- [x] **End-to-end integration tests (no mocks)** — `tests/test_e2e.py`.
- [x] **False-positive guard suite** — `tests/test_false_positives.py`, gates the whole
  benign corpus plus near-miss and carrier-question prompts.
- [x] **Per-category heuristic coverage** — agentic, indirect, persona classes added.
- [x] **CLI tests** — `tests/test_cli.py`.

- [x] **`db.py` tests** — `tests/test_db.py`, in-memory SQLite per test. Covers the
  `STORE_PAYLOADS=false` privacy path, filters, pagination, aggregates.

## Infrastructure

- [x] **Docker setup.**
- [x] **Rate limiting** — `slowapi`, per-IP.
- [x] **CI gate on lint, types, and tests** — `.github/workflows/ci.yml`.

## CLI

- [x] **`pif test` command**, now with `--explain` for per-layer evidence.

## Dashboard

- [x] **Event detail, time window, log export** — all present.

- [x] **Dashboard typechecks and builds in CI** — it had five `tsc` errors sitting on
  master; `npm run lint` never looked at them.

- [x] **Dashboard unit tests** — vitest over `lib/api.ts`, 12 cases, wired into CI.
  Found the log export broken: it asked for 1000 events past a server cap of 200 and
  threw into a try/finally with no catch. `fetchAllEvents` pages properly now, and
  the response type says `{events, limit, offset}` like the endpoint actually
  returns.

- [ ] **Still no component tests.** The components are display code; a jsdom runner
  costs more than it would catch. Revisit if they grow logic.

---

## Current state (2026-08-31)

- 265 Python tests + 12 dashboard tests passing. `ruff` and `mypy` clean (mypy was
  red on master for four errors in `semantic.py` — `model.encode` is typed as
  returning a Tensor).
- Eval: **F1 0.941, precision 0.955, recall 0.928** at threshold 0.40
  (69 injection / 117 benign held out). Baseline gated in CI.
- Heuristic false positives on the 588-prompt benign corpus: **0**.
- Corpus: 346 injection / 588 benign.
- Threshold stays 0.40. 0.35 wins on the held-out split and blocks "Tell me a joke"
  — see README §Threshold Calibration.

## Open

- Multi-turn crescendo recall is 0.71, the weakest category. 19 of 21 entries clear
  layer 1 untouched; the semantic layer carries them. A commitment-appeal pattern
  ("we've established", "building on what you agreed") is the obvious next lever and
  the obvious false-positive risk — an ordinary "as we discussed earlier" has the
  same shape. Needs measurement before it needs code.
- `heuristics.check` is now a ~250-line linear scan. Still cheap next to layer 2.
- 17 corpus entries on the lint list (hygiene, not false positives).
