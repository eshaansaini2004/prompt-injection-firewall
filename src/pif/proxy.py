"""
FastAPI app — proxy router + dashboard API + WebSocket.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from pif import db
from pif.detection import engine
from pif.models import AttackType, settings

logger = logging.getLogger(__name__)


def _warm_up_semantic() -> None:
    from pif.detection import semantic
    from pif.models import settings as _settings
    semantic._get_model()
    semantic._load_corpus(_settings.corpus_path)


limiter = Limiter(key_func=get_remote_address, default_limits=[])


def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"error": {"message": "Rate limit exceeded", "code": "rate_limit_exceeded"}},
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    await db.init_db()
    db.start_broadcast_loop()
    # Warm up the semantic layer in a thread pool so it's ready for the first request
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _warm_up_semantic)
        logger.info("semantic layer ready")
    except Exception as exc:
        logger.warning("semantic warm-up failed (will retry on first request): %s", exc)
    yield
    db.stop_broadcast_loop()
    await _http_client.aclose()


app = FastAPI(title="Prompt Injection Firewall", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)  # type: ignore[arg-type]


@app.middleware("http")
async def request_size_limit(request: Request, call_next: Any) -> Response:
    content_length = request.headers.get("content-length")
    if content_length is not None and int(content_length) > settings.max_request_size_bytes:
        return JSONResponse(
            status_code=413,
            content={"error": {"message": "Request body too large", "code": "request_too_large"}},
        )
    return await call_next(request)  # type: ignore[no-any-return]


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Firewall-Mode", "X-Firewall-Threshold", "X-Session-Id"],
)

_http_client = httpx.AsyncClient(timeout=60.0)

# Headers that should never be forwarded to downstream clients
_STRIP_HEADERS = {
    # Hop-by-hop
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    # Server fingerprinting
    "server", "x-powered-by", "x-request-id", "x-amzn-requestid",
    "x-amzn-trace-id", "cf-ray", "cf-cache-status",
}


def _safe_headers(headers: httpx.Headers) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in _STRIP_HEADERS}


def _require_dashboard_auth(authorization: str | None = Header(default=None)) -> None:
    if settings.dashboard_api_key is None:
        return
    if authorization != f"Bearer {settings.dashboard_api_key}":
        raise HTTPException(status_code=401, detail="Unauthorized")


# ---------------------------------------------------------------------------
# Proxy routes — drop-in OpenAI replacement
# ---------------------------------------------------------------------------

@app.post("/v1/chat/completions")
@limiter.limit(settings.rate_limit)
async def proxy_chat(
    request: Request,
    x_firewall_mode: str = Header(default="block"),
    x_firewall_threshold: float | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
) -> Response:
    body = await request.json()
    messages = body.get("messages", [])
    model = body.get("model", "unknown")

    result = await engine.analyze(messages, threshold=x_firewall_threshold)

    blocked = result.is_injection and x_firewall_mode != "monitor"

    task = asyncio.create_task(db.log_event(result, _messages_to_text(messages), model, blocked))
    task.add_done_callback(
        lambda t: logger.error("log_event failed: %s", t.exception()) if t.exception() else None
    )

    if blocked:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": "Request blocked by prompt injection firewall",
                    "type": "prompt_injection_detected",
                    "code": "injection_blocked",
                    "firewall": {
                        "attack_type": result.attack_type.value,
                        "confidence": result.confidence,
                        "matched_patterns": result.matched_patterns,
                    },
                }
            },
        )

    upstream_headers = {
        "Authorization": f"Bearer {settings.upstream_api_key}",
        "Content-Type": "application/json",
    }

    if body.get("stream") is True:
        async def _stream_response() -> AsyncGenerator[bytes, None]:
            try:
                async with _http_client.stream(
                    "POST",
                    f"{settings.upstream_llm_url}/chat/completions",
                    headers=upstream_headers,
                    content=await request.body(),
                ) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk
            except httpx.HTTPError as exc:
                logger.error("upstream stream error: %s", exc)
                yield b"data: [DONE]\n\n"

        return StreamingResponse(_stream_response(), media_type="text/event-stream")

    try:
        upstream_resp = await _http_client.post(
            f"{settings.upstream_llm_url}/chat/completions",
            headers=upstream_headers,
            content=await request.body(),
        )
    except httpx.HTTPError as exc:
        logger.error("upstream request error: %s", exc)
        return JSONResponse(
            status_code=502,
            content={"error": {"message": "Upstream request failed", "code": "bad_gateway"}},
        )

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=_safe_headers(upstream_resp.headers),
    )


@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_passthrough(request: Request, path: str) -> Response:
    """Passthrough for non-inspected endpoints (models, embeddings, etc.)."""
    try:
        upstream_resp = await _http_client.request(
            method=request.method,
            url=f"{settings.upstream_llm_url}/{path}",
            headers={
                "Authorization": f"Bearer {settings.upstream_api_key}",
                "Content-Type": request.headers.get("content-type", "application/json"),
            },
            content=await request.body(),
            params=dict(request.query_params),
        )
    except httpx.HTTPError as exc:
        logger.error("upstream passthrough error: %s", exc)
        return JSONResponse(
            status_code=502,
            content={"error": {"message": "Upstream request failed", "code": "bad_gateway"}},
        )

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=_safe_headers(upstream_resp.headers),
    )


# ---------------------------------------------------------------------------
# Dashboard API
# ---------------------------------------------------------------------------

@app.get("/api/stats")
async def api_stats(_: None = Depends(_require_dashboard_auth)) -> Any:
    return await db.get_stats()


@app.get("/api/events")
async def api_events(
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    attack_type: AttackType | None = Query(None),
    blocked_only: bool = Query(False),
    _: None = Depends(_require_dashboard_auth),
) -> Any:
    events = await db.get_events(
        limit=limit, offset=offset, attack_type=attack_type, blocked_only=blocked_only
    )
    return {"events": events, "limit": limit, "offset": offset}


@app.get("/api/events/{event_id}")
async def api_event(event_id: str, _: None = Depends(_require_dashboard_auth)) -> Any:
    event = await db.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.get("/api/timeline")
async def api_timeline(
    hours: int = Query(24, le=168), _: None = Depends(_require_dashboard_auth)
) -> Any:
    return await db.get_timeline(hours=hours)


@app.get("/api/attack-types")
async def api_attack_types(_: None = Depends(_require_dashboard_auth)) -> Any:
    return await db.get_attack_type_counts()


# ---------------------------------------------------------------------------
# WebSocket — real-time event stream
# ---------------------------------------------------------------------------

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    await websocket.accept()

    if settings.dashboard_api_key is not None:
        # Auth via first message so the key never appears in URLs or access logs.
        # Client sends: {"token": "<key>"}
        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
            msg = json.loads(raw)
            if msg.get("token") != settings.dashboard_api_key:
                await websocket.close(code=1008)
                return
        except (asyncio.TimeoutError, json.JSONDecodeError, KeyError):
            await websocket.close(code=1008)
            return
    queue = await db.broadcast_subscribe()
    try:
        while True:
            event = await queue.get()
            await websocket.send_text(event.model_dump_json())
    except WebSocketDisconnect:
        pass
    finally:
        await db.broadcast_unsubscribe(queue)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


def _messages_to_text(messages: list[dict[str, Any]]) -> str:
    return "\n".join(
        m.get("content", "") if isinstance(m.get("content"), str) else ""
        for m in messages
    )
