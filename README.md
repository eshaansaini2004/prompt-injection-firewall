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
| Adversarial Suffixes (GCG) | token-level gibberish suffixes, high-entropy character clusters |
| Multi-Turn Crescendo | gradual escalation across turns |
| Multimodal Injection | hidden text in images |
| Privilege Escalation | "developer mode", vendor impersonation |

**Layer 1 (heuristics)** runs synchronously in ~0.5ms. Confidence ≥ 0.65 skips layer 2.
**Layer 2 (semantic)** uses `all-MiniLM-L6-v2` + cosine similarity against 220 labeled attack examples and 507 benign prompts. Runs in a thread pool via `run_in_executor`. Per-category attack type classification from the embedding index.

Confidence threshold defaults to `0.50`. Override per-request with `X-Firewall-Threshold`.

### Threshold Calibration

Threshold was chosen by sweeping 0.30–0.95 on a held-out test set (44 injection, 101 benign) and picking the lowest value that keeps precision at 1.0 (zero false positives). Results at key operating points:

| Threshold | Precision | Recall | F1   | False Positives | False Negatives |
|-----------|-----------|--------|------|-----------------|-----------------|
| 0.30      | 0.872     | 0.932  | 0.90 | 6               | 3               |
| 0.35      | 0.911     | 0.932  | 0.92 | 4               | 3               |
| 0.40      | 0.930     | 0.909  | 0.92 | 3               | 4               |
| 0.45      | 0.949     | 0.841  | 0.89 | 2               | 7               |
| **0.50**  | **1.000** | **0.705** | **0.83** | **0** | **13** |
| 0.55      | 1.000     | 0.500  | 0.67 | 0               | 22              |
| 0.65      | 1.000     | 0.409  | 0.58 | 0               | 26              |
| 0.75      | 1.000     | 0.182  | 0.31 | 0               | 36              |

ROC-AUC is 0.987 across all thresholds. The default of 0.50 is the last point where precision stays perfect. Lower values improve recall further but introduce false positives that would block legitimate requests.

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
        ├── injections.jsonl   # 220 labeled attack examples (14 categories)
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
