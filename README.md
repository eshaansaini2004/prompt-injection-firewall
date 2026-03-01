# Prompt Injection Firewall

A drop-in OpenAI-compatible reverse proxy that detects and blocks prompt injection attacks before they reach the model. Change one line in your existing code — `base_url` — and every request gets screened.

Detection runs in two layers. A fast heuristic pass (regex + structural signals) handles the obvious stuff in under a millisecond. If that's inconclusive, a semantic layer computes embedding similarity against a labeled attack corpus using `sentence-transformers`. The slower path only runs when needed.

A real-time dashboard shows blocked requests, attack type breakdown, and a live event feed over WebSocket.

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
```

**Dashboard**

```bash
cd dashboard
npm install
npm run dev   # http://localhost:3001
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
| Obfuscation | base64, unicode tag block, ROT13 |
| Many-Shot Priming | repeated Q:/A: pairs |
| Privilege Escalation | "developer mode", vendor impersonation |
| + 5 more | adversarial suffixes, RAG poisoning, etc. |

**Layer 1 (heuristics)** runs synchronously in ~0.5ms. Returns confidence ≥ 0.65 → skip layer 2.
**Layer 2 (semantic)** uses `all-MiniLM-L6-v2` + cosine similarity. Runs in a thread pool via `run_in_executor`.

Confidence threshold defaults to `0.75`. Override per-request with `X-Firewall-Threshold`.

---

## Headers

| Header | Values | Effect |
|--------|--------|--------|
| `X-Firewall-Mode` | `block` (default), `monitor` | `monitor` logs but never blocks |
| `X-Firewall-Threshold` | float 0–1 | Override block threshold for this request |
| `X-Session-Id` | string | Tag events with a session identifier |

---

## API

The proxy exposes a dashboard REST API alongside the OpenAI passthrough:

```
GET  /api/stats            — aggregate counts and avg latency
GET  /api/events           — paginated event log (filter by type, blocked_only)
GET  /api/timeline?hours=N — hourly buckets for the last N hours
GET  /api/attack-types     — blocked count by attack category
WS   /ws/events            — real-time event stream
GET  /health               — liveness check
```

---

## Environment Variables

```env
DATABASE_URL=sqlite+aiosqlite:///./pif.db
UPSTREAM_LLM_URL=https://api.openai.com/v1
UPSTREAM_API_KEY=sk-...
CORPUS_PATH=src/pif/detection/corpus
BLOCK_THRESHOLD=0.75
STORE_PAYLOADS=false   # if true, stores full payload text; default stores hash + 200-char preview
```

---

## Testing

```bash
pytest                          # all tests
pytest tests/test_heuristics.py -v
pytest -k "injection" --tb=short
```

The semantic layer is mocked in tests — no model download needed to run the suite.

---

## Project Layout

```
src/pif/
├── proxy.py            # FastAPI app — single entry point
├── models.py           # Pydantic models, Settings, AttackType enum
├── db.py               # SQLAlchemy async DB layer (all queries live here)
├── cli.py              # Typer CLI: pif serve, pif logs, pif check-corpus
└── detection/
    ├── engine.py       # Orchestrator — heuristics → semantic
    ├── heuristics.py   # Regex + structural checks, synchronous
    ├── semantic.py     # Embedding similarity, blocking I/O
    └── corpus/
        ├── injections.jsonl   # 50 labeled attack examples
        └── benign.jsonl       # 30 benign prompts

dashboard/              # Next.js app (App Router)
├── app/page.tsx        # Single-page dashboard
└── lib/api.ts          # All backend calls

tests/
├── conftest.py
├── test_heuristics.py  # 41 tests, all attack categories + false positive checks
└── test_proxy.py       # Proxy logic with mocked engine/db
```
