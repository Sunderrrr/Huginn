"""Tag CRUD and VM↔tag assignment."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tag import Tag, VMTag


class TagError(Exception):
    """Raised on tag conflicts (e.g. duplicate name)."""


async def list_tags(session: AsyncSession) -> list[Tag]:
    result = await session.execute(select(Tag).order_by(Tag.name))
    return list(result.scalars().all())


async def get_tag(session: AsyncSession, tag_id: uuid.UUID) -> Tag | None:
    return await session.get(Tag, tag_id)


async def get_by_name(session: AsyncSession, name: str) -> Tag | None:
    result = await session.execute(select(Tag).where(Tag.name == name))
    return result.scalar_one_or_none()


async def create_tag(session: AsyncSession, *, name: str, color: str) -> Tag:
    if await get_by_name(session, name) is not None:
        raise TagError("a tag with that name already exists")
    tag = Tag(name=name, color=color)
    session.add(tag)
    await session.flush()
    return tag


async def update_tag(
    session: AsyncSession, tag: Tag, *, name: str | None, color: str | None
) -> Tag:
    if name is not None and name != tag.name:
        if await get_by_name(session, name) is not None:
            raise TagError("a tag with that name already exists")
        tag.name = name
    if color is not None:
        tag.color = color
    await session.flush()
    return tag


async def delete_tag(session: AsyncSession, tag: Tag) -> None:
    await session.delete(tag)


async def set_vm_tags(
    session: AsyncSession, vm_id: uuid.UUID, tag_ids: list[uuid.UUID]
) -> None:
    """Replace the set of tags on a VM (mirror of _set_user_vm_access)."""
    existing = await session.execute(select(VMTag).where(VMTag.vm_id == vm_id))
    for row in existing.scalars().all():
        await session.delete(row)
    for tag_id in tag_ids:
        session.add(VMTag(vm_id=vm_id, tag_id=tag_id))
    await session.flush()


async def vm_ids_for_tags(
    session: AsyncSession, tag_ids: list[uuid.UUID]
) -> list[uuid.UUID]:
    """VM ids carrying at least one of the given tags."""
    if not tag_ids:
        return []
    result = await session.execute(
        select(VMTag.vm_id).where(VMTag.tag_id.in_(tag_ids)).distinct()
    )
    return [row[0] for row in result.all()]


async def load_tags_for_vms(
    session: AsyncSession, vm_ids: list[uuid.UUID]
) -> dict[uuid.UUID, list[Tag]]:
    """Map each VM id to its tags in one query (avoids N+1)."""
    if not vm_ids:
        return {}
    result = await session.execute(
        select(VMTag.vm_id, Tag)
        .join(Tag, Tag.id == VMTag.tag_id)
        .where(VMTag.vm_id.in_(vm_ids))
        .order_by(Tag.name)
    )
    out: dict[uuid.UUID, list[Tag]] = {}
    for vm_id, tag in result.all():
        out.setdefault(vm_id, []).append(tag)
    return out
