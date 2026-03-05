"""
Database layer. All DB access lives here, nowhere else.
"""
from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from pif.models import (
    AttackEvent,
    AttackType,
    AttackTypeCount,
    DetectionResult,
    StatsResponse,
    TimelineBucket,
    settings,
)

engine = create_async_engine(settings.database_url, echo=False)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

# WebSocket broadcast queue — proxy writes, WS handler reads
_broadcast_queue: asyncio.Queue[AttackEvent] = asyncio.Queue()


class Base(DeclarativeBase):
    pass


class AttackEventRow(Base):
    __tablename__ = "attack_events"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    model = Column(String, nullable=True)
    attack_type = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    blocked = Column(Boolean, nullable=False)
    payload_hash = Column(String, nullable=False)
    payload_preview = Column(Text, nullable=True)
    layer_triggered = Column(Integer, nullable=False)
    latency_ms = Column(Float, nullable=False)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)



async def log_event(
    result: DetectionResult,
    payload: str,
    model: str | None,
    blocked: bool,
) -> AttackEvent:
    payload_hash = hashlib.sha256(payload.encode()).hexdigest()
    preview = payload[:200] if settings.store_payloads else None

    row = AttackEventRow(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        model=model,
        attack_type=result.attack_type.value,
        confidence=result.confidence,
        blocked=blocked,
        payload_hash=payload_hash,
        payload_preview=preview,
        layer_triggered=result.layer_triggered,
        latency_ms=result.latency_ms,
    )

    async with SessionLocal() as session:
        session.add(row)
        await session.commit()
        await session.refresh(row)

    event = _row_to_model(row)
    await _broadcast_queue.put(event)
    return event


async def get_events(
    limit: int = 50,
    offset: int = 0,
    attack_type: AttackType | None = None,
    blocked_only: bool = False,
) -> list[AttackEvent]:
    async with SessionLocal() as session:
        q = select(AttackEventRow).order_by(AttackEventRow.timestamp.desc())
        if attack_type:
            q = q.where(AttackEventRow.attack_type == attack_type.value)
        if blocked_only:
            q = q.where(AttackEventRow.blocked.is_(True))
        q = q.limit(limit).offset(offset)
        result = await session.execute(q)
        return [_row_to_model(r) for r in result.scalars()]


async def get_event(event_id: str) -> AttackEvent | None:
    async with SessionLocal() as session:
        result = await session.execute(
            select(AttackEventRow).where(AttackEventRow.id == event_id)
        )
        row = result.scalar_one_or_none()
        return _row_to_model(row) if row else None


async def get_stats() -> StatsResponse:
    async with SessionLocal() as session:
        total = (await session.execute(select(func.count(AttackEventRow.id)))).scalar() or 0
        blocked_total = (
            await session.execute(
                select(func.count(AttackEventRow.id)).where(AttackEventRow.blocked.is_(True))
            )
        ).scalar() or 0

        today = datetime.now(timezone.utc).date()
        blocked_today = (
            await session.execute(
                select(func.count(AttackEventRow.id)).where(
                    AttackEventRow.blocked.is_(True),
                    func.date(AttackEventRow.timestamp) == today,
                )
            )
        ).scalar() or 0

        avg_latency = (
            await session.execute(select(func.avg(AttackEventRow.latency_ms)))
        ).scalar() or 0.0

    return StatsResponse(
        total_requests=total,
        blocked_total=blocked_total,
        blocked_today=blocked_today,
        block_rate=round(blocked_total / total, 4) if total else 0.0,
        avg_latency_ms=round(avg_latency, 2),
    )


async def get_timeline(hours: int = 24) -> list[TimelineBucket]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    async with SessionLocal() as session:
        result = await session.execute(
            select(
                func.strftime("%Y-%m-%dT%H:00:00", AttackEventRow.timestamp).label("hour"),
                func.count(AttackEventRow.id).label("total"),
                func.sum(AttackEventRow.blocked.cast(Integer)).label("blocked"),
            )
            .where(AttackEventRow.timestamp >= since)
            .group_by("hour")
            .order_by("hour")
        )
        return [
            TimelineBucket(hour=row.hour, total=row.total, blocked=row.blocked or 0)
            for row in result
        ]


async def get_attack_type_counts() -> list[AttackTypeCount]:
    async with SessionLocal() as session:
        result = await session.execute(
            select(
                AttackEventRow.attack_type,
                func.count(AttackEventRow.id).label("count"),
            )
            .where(AttackEventRow.blocked.is_(True))
            .group_by(AttackEventRow.attack_type)
            .order_by(func.count(AttackEventRow.id).desc())
        )
        return [
            AttackTypeCount(attack_type=AttackType(row.attack_type), count=row.count)
            for row in result
        ]


async def broadcast_subscribe() -> asyncio.Queue[AttackEvent]:
    """Each WS connection gets its own queue fed from the broadcast."""
    q: asyncio.Queue[AttackEvent] = asyncio.Queue()
    _subscribers.append(q)
    return q


async def broadcast_unsubscribe(q: asyncio.Queue[AttackEvent]) -> None:
    try:
        _subscribers.remove(q)
    except ValueError:
        pass


_subscribers: list[asyncio.Queue[AttackEvent]] = []


async def _broadcast_loop() -> None:
    """Drains the central queue and fans out to all subscriber queues."""
    while True:
        event = await _broadcast_queue.get()
        for sub in list(_subscribers):
            await sub.put(event)


def start_broadcast_loop() -> None:
    asyncio.create_task(_broadcast_loop())


def _row_to_model(row: AttackEventRow) -> AttackEvent:
    return AttackEvent(
        id=row.id,
        timestamp=row.timestamp.isoformat() if row.timestamp else "",
        model=row.model,
        attack_type=AttackType(row.attack_type),
        confidence=row.confidence,
        blocked=row.blocked,
        payload_hash=row.payload_hash,
        payload_preview=row.payload_preview,
        layer_triggered=row.layer_triggered,
        latency_ms=row.latency_ms,
    )
