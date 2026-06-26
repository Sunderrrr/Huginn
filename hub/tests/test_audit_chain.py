"""The audit log is append-only and tamper-evident."""

from __future__ import annotations

import pytest

from app.core import audit
from app.models.audit import AuditLog
from app.models.enums import ActorType


@pytest.mark.asyncio
async def test_chain_links_and_verifies(session) -> None:
    await audit.record(
        session, actor_type=ActorType.user, actor_id="admin", event_type="login"
    )
    await audit.record(
        session, actor_type=ActorType.agent, actor_id="hermes", event_type="execute_action"
    )
    await session.commit()

    assert await audit.verify_chain(session) is True


@pytest.mark.asyncio
async def test_first_entry_links_to_genesis(session) -> None:
    entry = await audit.record(
        session, actor_type=ActorType.system, actor_id="hub", event_type="startup"
    )
    assert entry.prev_hash == audit.GENESIS_HASH
    assert len(entry.row_hash) == 64


@pytest.mark.asyncio
async def test_tampering_breaks_the_chain(session) -> None:
    await audit.record(
        session, actor_type=ActorType.user, actor_id="admin", event_type="login"
    )
    e2 = await audit.record(
        session,
        actor_type=ActorType.user,
        actor_id="admin",
        event_type="execute_command",
        command="rm -rf /tmp/x",
    )
    await session.commit()

    # Simulate someone editing a stored row after the fact.
    e2.command = "echo harmless"
    await session.commit()

    assert await audit.verify_chain(session) is False


@pytest.mark.asyncio
async def test_records_persist_in_order(session) -> None:
    for i in range(3):
        await audit.record(
            session, actor_type=ActorType.system, actor_id="hub", event_type=f"e{i}"
        )
    await session.commit()
    rows = (await session.execute(__import__("sqlalchemy").select(AuditLog))).scalars().all()
    assert [r.event_type for r in rows] == ["e0", "e1", "e2"]
