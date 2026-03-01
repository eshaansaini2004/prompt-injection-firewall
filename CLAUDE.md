# Prompt Injection Firewall (PIF)

A reverse proxy that sits in front of any LLM API endpoint and intercepts requests to detect
prompt injection attacks before they reach the model. Detection runs in two layers: fast
heuristic pattern matching, then semantic similarity against a known-attack corpus.

The dashboard (Next.js) is a separate app in the same repo. Treat them as two independent
projects that happen to share a git history.

---

## Architecture

```
Request → PIF Proxy (FastAPI) → Detection Engine → upstream LLM API
                                      │
                              ┌───────┴────────┐
                         Heuristics        Semantic
                         (regex/rules)     (embeddings vs corpus)
```

**Backend (`src/pif/`)**
- `proxy.py` — FastAPI app, single entry point. Receives requests, calls the engine, proxies or blocks.
- `detection/engine.py` — Orchestrates heuristic + semantic checks. Returns a `DetectionResult`.
- `detection/heuristics.py` — Pattern-based checks (regex, keyword lists, entropy scoring). Fast, synchronous, runs first.
- `detection/semantic.py` — Embedding similarity against `detection/corpus/`. Slower, runs only if heuristics don't already flag.
- `detection/corpus/` — Curated attack examples used to build the vector index. Changing files here requires re-indexing.
- `models.py` — Pydantic models shared across the app. Source of truth for request/response shapes.
- `db.py` — Database layer (log storage for flagged requests). All DB access goes through here, nowhere else.
- `cli.py` — Typer CLI for admin tasks: re-indexing corpus, inspecting logs, running the server.

**Dashboard (`dashboard/`)**
- Standard Next.js app (App Router). Reads from the PIF backend via REST + WebSocket. No shared code with the Python side.

---

## Attack Categories Covered

14 categories based on Perez & Ribeiro (2022), Greshake et al. (2023), and OWASP LLM Top 10:

1. **Direct Injection** — "ignore all previous instructions"
2. **Prompt Leaking** — extracting system prompts
3. **Jailbreaks (DAN/AIM/Persona)** — alternate persona bypasses
4. **Roleplay/Emotional Framing** — grandma exploit, story framing
5. **Hypothetical/Research Framing** — "for educational purposes"
6. **Indirect Injection** — malicious content in retrieved docs
7. **RAG/Vector DB Poisoning** — poisoned retrieval chunks
8. **Obfuscation/Encoding** — base64, unicode tags, ROT13
9. **Multi-Turn Crescendo** — gradual escalation across turns
10. **Many-Shot Jailbreaking** — priming with fake Q&A examples
11. **Agentic/Tool-Use Injection** — attacks targeting tool-calling agents
12. **Adversarial Suffixes (GCG)** — token-level gibberish suffixes
13. **Multimodal Injection** — hidden text in images
14. **Privilege Escalation** — "developer mode," vendor impersonation

---

## Commands

### Backend

```bash
# Install (from repo root)
pip install -e ".[dev]"

# Run the proxy
uvicorn pif.proxy:app --reload --port 8000
# or
python -m pif.cli serve

# Re-index corpus after adding attack examples
python -m pif.cli reindex

# Run tests
pytest
pytest tests/test_heuristics.py -v
pytest -k "injection" --tb=short

# Type checking + linting
mypy src/
ruff check src/
```

### Dashboard

```bash
cd dashboard
npm install
npm run dev        # :3001
npm run build
npm run lint
```

---

## Environment Variables

Backend (`.env` at repo root):
```
DATABASE_URL=sqlite:///./pif.db
UPSTREAM_LLM_URL=https://api.openai.com/v1
UPSTREAM_API_KEY=sk-...
CORPUS_PATH=src/pif/detection/corpus
BLOCK_THRESHOLD=0.75
STORE_PAYLOADS=false
```

Dashboard (`.env.local` in `dashboard/`):
```
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## Coding Conventions

### Python
- Type hints on every function signature.
- Pydantic models in `models.py` for anything crossing a boundary.
- Async route handlers in `proxy.py`. `heuristics.py` is sync (CPU-bound, fine).
- `semantic.py` does blocking I/O — run via `asyncio.run_in_executor` if called from async context.
- Absolute imports only (`from pif.models import ...`).
- Raise typed exceptions from detection layer, catch at proxy layer.
- Tests in `tests/`, mirroring `src/pif/` structure.

### TypeScript / Next.js
- App Router only.
- Server Components where possible, client components only for interactivity.
- Tailwind only, no inline styles.
- All backend API calls go through `lib/api.ts`.

---

## Gotchas

**Corpus changes require reindex.** Adding/editing files in `detection/corpus/` does nothing until you run `python -m pif.cli reindex`. The semantic layer will use a stale or missing index otherwise.

**`db.py` owns the database.** No SQLAlchemy sessions or raw queries anywhere else. New queries go in `db.py`.

**Semantic layer blocks the event loop.** `semantic.py` uses sentence-transformers which is synchronous. Always call via `run_in_executor` from async contexts.

**Proxy is stateless between requests.** No caching detection results in globals or request state — only the DB write is a side effect.

**`detection/corpus/` is not for runtime data.** It's curated attack examples checked into git.

**`pyproject.toml` is the single source of truth.** No separate `requirements.txt`, `setup.py`, or `pytest.ini`.

**False positives matter as much as detection rate.** A firewall that blocks legitimate requests is useless. The benign corpus in `tests/` is as important as the attack corpus.

---

## Project Layout

```
prompt-injection-firewall/
├── CLAUDE.md
├── pyproject.toml
├── .env.example
├── src/pif/
│   ├── __init__.py
│   ├── proxy.py            # FastAPI app
│   ├── models.py           # Pydantic models
│   ├── db.py               # DB access layer
│   ├── cli.py              # Typer CLI
│   └── detection/
│       ├── __init__.py
│       ├── engine.py       # Orchestrator
│       ├── heuristics.py   # Pattern checks
│       ├── semantic.py     # Embedding similarity
│       └── corpus/         # Attack examples (git-tracked)
│           ├── injections.jsonl
│           └── benign.jsonl
├── dashboard/              # Next.js app
└── tests/
    ├── conftest.py
    ├── test_heuristics.py
    ├── test_semantic.py
    ├── test_engine.py
    └── test_proxy.py
```
