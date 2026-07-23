# Prompt Injection Firewall

A drop-in OpenAI-compatible reverse proxy that detects and blocks prompt injection attacks before they reach the model. Change one line in your existing code — `base_url` — and every request gets screened.

Detection runs in two layers. A fast heuristic pass (regex + structural signals) handles the obvious stuff in under a millisecond. If that's inconclusive, a semantic layer computes embedding similarity against a labeled attack corpus using `sentence-transformers`. The slower path only runs when needed.

A real-time dashboard shows blocked requests, attack type breakdown, time window filtering, and a live event feed over WebSocket.

---

## Architecture

```
Request → PIF Proxy (FastAPI) → Detection Engine → upstream LLM API
                                      │
                              ┌───────┴────────┐
                         Heuristics        Semantic
                         (regex/rules)     (embeddings vs corpus)
                              │
                          DB + WebSocket broadcast
```

---

## Quick Start

**Backend**

```bash
pip install -e ".[dev]"

# copy and fill in your upstream API key
cp .env.example .env

uvicorn pif.proxy:app --port 8000
# or
pif serve
```

**Dashboard**

```bash
cd dashboard
npm install
npm run dev   # http://localhost:3001
```

**Docker**

```bash
docker-compose up
```

**Drop-in replacement** — just point your OpenAI client at the proxy:

```python
from openai import OpenAI

client = OpenAI(
    api_key="your-key",
    base_url="http://localhost:8000/v1",
)
```

Injections get blocked with a `400`. Everything else passes through transparently.

**Test a prompt from the CLI**

```bash
echo "Ignore all previous instructions" | pif test
```

---

## Detection

**14 attack categories** based on Perez & Ribeiro (2022), Greshake et al. (2023), and OWASP LLM Top 10:

| Category | Example |
|----------|---------|
| Direct Injection | "ignore all previous instructions" |
| Prompt Leaking | "repeat your system prompt verbatim" |
| Jailbreak / Persona | DAN, AIM, DevMode |
| Roleplay Framing | grandma exploit, "stay in character" |
| Hypothetical Framing | "for educational purposes only" |
| Indirect Injection | malicious content in retrieved docs |
| RAG / Vector DB Poisoning | poisoned retrieval chunks |
| Obfuscation | base64, unicode tag block, ROT13 |
| Many-Shot Priming | repeated Q:/A: pairs |
| Agentic / Tool-Use Injection | fake `{"function": ...}` calls, `<tool_result>` tag poisoning |
| Adversarial Suffixes (GCG) | token-level gibberish suffixes — detected via entropy (>4.5 bits/char) and repeated punctuation clusters |
| Multi-Turn Crescendo | gradual escalation across turns |
| Multimodal Injection | hidden text in images |
| Privilege Escalation | "developer mode", vendor impersonation |

**Layer 1 (heuristics)** runs synchronously in ~0.5ms. Confidence ≥ 0.65 skips layer 2.
**Layer 2 (semantic)** uses `all-MiniLM-L6-v2` + cosine similarity against 346 labeled attack examples and 547 benign prompts. Runs in a thread pool via `run_in_executor`. Attack type comes from a top-k vote over per-category embeddings.

Confidence threshold defaults to `0.40`. Override per-request with `X-Firewall-Threshold`.

### Threshold Calibration

Swept 0.30–0.95 on a held-out test set (69 injection, 109 benign). Results at key operating points:

| Threshold | Precision | Recall | F1   | False Positives | False Negatives |
|-----------|-----------|--------|------|-----------------|-----------------|
| 0.30      | 0.941     | 0.928  | 0.93 | 4               | 5               |
| 0.35      | 0.940     | 0.913  | 0.93 | 4               | 6               |
| **0.40**  | **0.968** | **0.884** | **0.92** | **2** | **8** |
| 0.45      | 0.967     | 0.841  | 0.90 | 2               | 11              |
| 0.50      | 0.981     | 0.754  | 0.85 | 1               | 17              |
| 0.55      | 0.978     | 0.652  | 0.78 | 1               | 24              |
| 0.65      | 1.000     | 0.507  | 0.67 | 0               | 34              |
| 0.75      | 1.000     | 0.188  | 0.32 | 0               | 56              |

ROC-AUC is 0.982 across all thresholds.

The default moved from 0.50 to 0.40 once the benign corpus grew past 500 prompts. 0.50 was originally chosen as the last zero-FP point, but that was an artifact of a 101-prompt benign test set — on the larger set it costs 13 points of recall to avoid a single false positive. Chasing precision 1.0 gets expensive fast: 0.65 buys the last two FPs for 38 points of recall.

### Known Limitations: GCG Adversarial Suffixes

GCG (Greedy Coordinate Gradient) attacks from Zou et al. 2023 append optimized token sequences to otherwise normal prompts to manipulate model behavior. Detection in PIF relies on two statistical heuristics:

1. **Entropy check** — a 30-character sliding window with Shannon entropy > 4.5 bits/char and > 55% non-alphanumeric characters triggers `ADVERSARIAL_SUFFIX` at confidence 0.85.
2. **Repeated token clusters** — five or more consecutive unusual punctuation tokens (`! ! ! ! !`, `} } } { }`) trigger the same category.

**What these catch:** high-entropy gibberish suffixes, repeated token sequences, and GCG outputs that produce statistical anomalies. Measured recall on the test corpus is **1.00 (2/2 adversarial\_suffix examples in the held-out split)**.

**What they miss:** GCG suffixes specifically optimized to stay below the entropy threshold or avoid token repetition. An adversary who white-box attacks the entropy check can craft a suffix that reads as moderate-entropy text while still transferring adversarially. The semantic layer provides no additional defense here — GCG suffixes lack the natural-language semantics that cosine similarity relies on.

This is a fundamental constraint: statistical heuristics catch GCG in practice because real-world GCG outputs are high-entropy, but they offer no guarantee against a targeted adversary who can probe the detector. Robust GCG defense would require perplexity filtering (using a separate language model to score token sequences) or input smoothing, both out of scope for this project.

---

## Headers

| Header | Values | Effect |
|--------|--------|--------|
| `X-Firewall-Mode` | `block` (default), `monitor` | `monitor` logs but never blocks |
| `X-Firewall-Threshold` | float 0–1 | Override block threshold for this request |
| `X-Session-Id` | string | Tag events with a session identifier |

---

## Rate Limiting

`/v1/chat/completions` is rate-limited per IP. Default: `60/minute`. Override with `RATE_LIMIT` in `.env`.

---

## API

The proxy exposes a dashboard REST API alongside the OpenAI passthrough:

```
GET  /api/stats              — aggregate counts and avg latency
GET  /api/events             — paginated event log (filter by type, blocked_only)
GET  /api/events/{event_id}  — single event detail
GET  /api/timeline?hours=N   — hourly buckets for the last N hours (max 168)
GET  /api/attack-types       — blocked count by attack category
WS   /ws/events              — real-time event stream (auth via first message)
GET  /health                 — liveness check
```

WebSocket auth: if `DASHBOARD_API_KEY` is set, the client must send `{"token": "<key>"}` as the first message after connecting.

---

## Environment Variables

```env
DATABASE_URL=sqlite+aiosqlite:///./pif.db
UPSTREAM_LLM_URL=https://api.openai.com/v1
UPSTREAM_API_KEY=sk-...
CORPUS_PATH=src/pif/detection/corpus
BLOCK_THRESHOLD=0.75
RATE_LIMIT=60/minute
STORE_PAYLOADS=false   # if true, stores full payload text; default stores hash + 200-char preview
DASHBOARD_API_KEY=     # optional; if set, all dashboard endpoints require Bearer auth
```

---

## Testing

```bash
pytest                          # all 91 tests
pytest tests/test_heuristics.py -v
pytest -k "injection" --tb=short
```

The semantic layer is mocked in engine tests — no model download needed for the core suite. The `tests/test_semantic.py` tests require the model and are marked `slow`.

---

## Project Layout

```
src/pif/
├── proxy.py            # FastAPI app — single entry point
├── models.py           # Pydantic models, Settings, AttackType enum
├── db.py               # SQLAlchemy async DB layer (all queries live here)
├── cli.py              # Typer CLI: pif serve, pif test, pif reindex, pif logs
└── detection/
    ├── engine.py       # Orchestrator — heuristics → semantic
    ├── heuristics.py   # Regex + structural checks + GCG entropy, synchronous
    ├── semantic.py     # Embedding similarity, LRU cache, per-category classification
    └── corpus/
        ├── injections.jsonl   # 241 labeled attack examples (14 categories)
        └── benign.jsonl       # 121 benign prompts

dashboard/              # Next.js app (App Router)
├── app/page.tsx        # Dashboard with time window selector and log export
├── app/components/     # EventDetailPanel and other components
└── lib/api.ts          # All backend calls

tests/
├── conftest.py
├── test_heuristics.py  # 53 tests — all attack categories + false positive checks
├── test_engine.py      # 21 tests — engine orchestration (mocked layers)
├── test_semantic.py    # 8 tests — semantic layer (slow, requires model)
└── test_proxy.py       # 9 tests — proxy routing with mocked engine/db
```
