"""
Storage layer tests. Each test gets a fresh in-memory SQLite database — no fixtures
shared with the proxy suite, and nothing touches ./pif.db.

The privacy path matters most here: STORE_PAYLOADS defaults to false, and a bug that
silently persists prompt text is the kind you find out about from someone else.
"""
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from pif import db
from pif.models import AttackType, DetectionResult


@pytest.fixture
async def fresh_db(monkeypatch):
    """Point db.py at a private in-memory database for the duration of one test."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    monkeypatch.setattr(db, "engine", engine)
    monkeypatch.setattr(db, "SessionLocal", session_factory)

    async with engine.begin() as conn:
        await conn.run_sync(db.Base.metadata.create_all)

    # log_event pushes onto this; drain it per test so queues don't leak between them.
    import asyncio

    monkeypatch.setattr(db, "_broadcast_queue", asyncio.Queue())

    yield
    await engine.dispose()


def _result(
    attack_type: AttackType = AttackType.DIRECT_INJECTION,
    confidence: float = 0.9,
) -> DetectionResult:
    return DetectionResult(
        is_injection=True,
        confidence=confidence,
        attack_type=attack_type,
        matched_patterns=["ignore_previous_instructions"],
        layer_triggered=1,
        latency_ms=1.2,
    )


class TestPayloadPrivacy:
    async def test_payload_text_is_not_stored_by_default(self, fresh_db, monkeypatch):
        monkeypatch.setattr(db.settings, "store_payloads", False)
        secret = "my password is hunter2 and my card is 4111111111111111"

        event = await db.log_event(_result(), secret, "gpt-4", blocked=True)

        assert event.payload_preview is None
        stored = await db.get_event(event.id)
        assert stored is not None
        assert stored.payload_preview is None

    async def test_payload_preview_stored_when_enabled(self, fresh_db, monkeypatch):
        monkeypatch.setattr(db.settings, "store_payloads", True)

        event = await db.log_event(_result(), "ignore all instructions", "gpt-4", True)

        assert event.payload_preview == "ignore all instructions"

    async def test_preview_is_truncated_to_200_chars(self, fresh_db, monkeypatch):
        monkeypatch.setattr(db.settings, "store_payloads", True)

        event = await db.log_event(_result(), "x" * 500, "gpt-4", blocked=True)

        assert event.payload_preview is not None
        assert len(event.payload_preview) == 200

    async def test_hash_is_stored_regardless(self, fresh_db, monkeypatch):
        monkeypatch.setattr(db.settings, "store_payloads", False)

        event = await db.log_event(_result(), "some prompt", "gpt-4", blocked=True)

        # sha256 of the payload — same input, same hash, no plaintext.
        assert len(event.payload_hash) == 64
        again = await db.log_event(_result(), "some prompt", "gpt-4", blocked=True)
        assert again.payload_hash == event.payload_hash


class TestEventQueries:
    async def test_events_come_back_newest_first(self, fresh_db):
        for conf in (0.5, 0.7, 0.9):
            await db.log_event(_result(confidence=conf), "p", "gpt-4", blocked=True)

        events = await db.get_events(limit=10)
        assert len(events) == 3
        timestamps = [e.timestamp for e in events]
        assert timestamps == sorted(timestamps, reverse=True)

    async def test_filter_by_attack_type(self, fresh_db):
        await db.log_event(_result(AttackType.DIRECT_INJECTION), "a", None, True)
        await db.log_event(_result(AttackType.OBFUSCATION), "b", None, True)

        events = await db.get_events(attack_type=AttackType.OBFUSCATION)
        assert [e.attack_type for e in events] == [AttackType.OBFUSCATION]

    async def test_blocked_only_excludes_monitored(self, fresh_db):
        await db.log_event(_result(), "blocked one", None, blocked=True)
        await db.log_event(_result(), "monitored one", None, blocked=False)

        assert len(await db.get_events()) == 2
        assert len(await db.get_events(blocked_only=True)) == 1

    async def test_limit_and_offset_paginate(self, fresh_db):
        for _ in range(5):
            await db.log_event(_result(), "p", None, blocked=True)

        page1 = await db.get_events(limit=2, offset=0)
        page2 = await db.get_events(limit=2, offset=2)

        assert len(page1) == len(page2) == 2
        assert {e.id for e in page1}.isdisjoint({e.id for e in page2})

    async def test_get_event_returns_none_for_unknown_id(self, fresh_db):
        assert await db.get_event("does-not-exist") is None


class TestAggregates:
    async def test_attack_type_counts_only_count_blocked(self, fresh_db):
        await db.log_event(_result(AttackType.OBFUSCATION), "a", None, blocked=True)
        await db.log_event(_result(AttackType.OBFUSCATION), "b", None, blocked=True)
        await db.log_event(_result(AttackType.OBFUSCATION), "c", None, blocked=False)

        counts = {c.attack_type: c.count for c in await db.get_attack_type_counts()}
        assert counts == {AttackType.OBFUSCATION: 2}

    async def test_stats_reflect_logged_events(self, fresh_db):
        await db.log_event(_result(), "a", None, blocked=True)
        await db.log_event(_result(), "b", None, blocked=False)

        stats = await db.get_stats()
        assert stats.total_requests == 2
        assert stats.blocked_total == 1
