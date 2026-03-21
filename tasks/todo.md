# PIF — Todo

## Detection

- [ ] **Entropy scoring + GCG adversarial suffix patterns**
  Implement entropy scoring in `heuristics.py`. Add heuristic patterns for GCG-style token gibberish (high Shannon entropy, unusual char distribution). The enum exists, zero patterns do.

- [ ] **Agentic / tool-use injection patterns**
  Add heuristics for function-calling attacks — JSON-embedded instruction injection, tool result poisoning, `{"function": ...}` hijacking patterns.

- [ ] **Multi-turn crescendo detection**
  Pass conversation history through the engine and check for escalation gradient across turns. Engine currently only sees the latest message.

## Semantic Layer

- [ ] **Expand corpus: 50→300 injections, 30→150 benign**
  More examples = better recall. Covers edge cases the current 50 don't. Run `pif reindex` after.

- [ ] **Embedding cache**
  Cache embeddings in memory keyed on input hash. Cuts semantic latency ~80% for repeated or similar inputs. Simple LRU, no external deps.

- [ ] **Attack type classification in semantic layer**
  Semantic hits always return `DIRECT_INJECTION`. Use per-category subcorpora or a lightweight classifier on top of the similarity score to return the real attack type.

## Testing

- [ ] **test_engine.py — orchestration coverage**
  Fast-path logic, threshold merging, layer selection, empty input handling. Currently zero coverage on the thing that ties everything together.

- [ ] **Streaming response tests**
  The streaming path in `proxy.py` is entirely untested. Mock the upstream and verify chunked SSE responses flow through correctly.

- [ ] **End-to-end integration tests (no mocks)**
  Run both detection layers together against known attack/benign inputs and assert on final block/pass decision.

## Infrastructure

- [ ] **Docker setup**
  `Dockerfile` for the backend + `docker-compose.yml` wiring backend + dashboard. Makes local dev and deployment non-painful.

- [ ] **Rate limiting**
  Semantic checks run in a thread pool — sustained traffic can saturate it. Add per-IP or per-API-key rate limiting via `slowapi` or middleware.

## CLI

- [ ] **`pif test` command**
  Pipe a prompt in, get detection result back. Essential for validating corpus changes without spinning up the proxy. Should show confidence, attack type, layer, matched patterns.

- [ ] **`pif reindex` hooked to corpus changes**
  Right now reindex is manual. Add a file watcher option or at minimum a startup check that warns if corpus files are newer than the index.

## Dashboard

- [ ] **Event detail / payload inspection**
  Click an event and see the full payload, matched patterns, confidence breakdown. Currently you can only see the feed summary.

- [ ] **Configurable time window on chart**
  1h / 6h / 24h / 7d selector on the timeline chart.

- [ ] **Log export**
  Download filtered events as CSV or JSON for offline analysis.
