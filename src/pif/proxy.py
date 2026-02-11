"""
FastAPI app — proxy router + dashboard API + WebSocket.
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from pif import db
from pif.detection import engine
from pif.models import AttackType, settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    await db.init_db()
    db.start_broadcast_loop()
    yield


app = FastAPI(title="Prompt Injection Firewall", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_http_client = httpx.AsyncClient(timeout=60.0)


# ---------------------------------------------------------------------------
# Proxy routes — drop-in OpenAI replacement
# ---------------------------------------------------------------------------

@app.post("/v1/chat/completions")
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

    await db.log_event(result, _messages_to_text(messages), model, blocked)

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

    # Forward to upstream
    upstream_resp = await _http_client.post(
        f"{settings.upstream_llm_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {settings.upstream_api_key}",
            "Content-Type": "application/json",
        },
        content=await request.body(),
    )

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=dict(upstream_resp.headers),
    )


@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_passthrough(request: Request, path: str) -> Response:
    """Passthrough for non-inspected endpoints (models, embeddings, etc.)."""
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
    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=dict(upstream_resp.headers),
    )


# ---------------------------------------------------------------------------
# Dashboard API
# ---------------------------------------------------------------------------

@app.get("/api/stats")
async def api_stats() -> Any:
    return await db.get_stats()


@app.get("/api/events")
async def api_events(
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    attack_type: AttackType | None = Query(None),
    blocked_only: bool = Query(False),
) -> Any:
    events = await db.get_events(limit=limit, offset=offset, attack_type=attack_type, blocked_only=blocked_only)
    return {"events": events, "limit": limit, "offset": offset}


@app.get("/api/events/{event_id}")
async def api_event(event_id: str) -> Any:
    event = await db.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.get("/api/timeline")
async def api_timeline(hours: int = Query(24, le=168)) -> Any:
    return await db.get_timeline(hours=hours)


@app.get("/api/attack-types")
async def api_attack_types() -> Any:
    return await db.get_attack_type_counts()


# ---------------------------------------------------------------------------
# WebSocket — real-time event stream
# ---------------------------------------------------------------------------

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    await websocket.accept()
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


def _messages_to_text(messages: list[dict]) -> str:
    return "\n".join(
        m.get("content", "") if isinstance(m.get("content"), str) else ""
        for m in messages
    )
