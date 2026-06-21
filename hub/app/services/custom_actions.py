"""Admin-defined custom commands: CRUD + per-VM authorization.

A custom action is an ordered list of fixed argv vectors (one per command line),
each run with no shell, that a VM in ``custom``/``unrestricted`` mode may run if it
carries one of the action's allowed tags. Lines are parsed/validated here so a
definition can never carry a shell or malformed element.
"""

from __future__ import annotations

import shlex
import uuid
from collections.abc import Sequence

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.custom_action import CustomAction, CustomActionTag
from app.models.tag import VMTag

_MAX_COMMANDS = 32
_MAX_ARGV = 64
_MAX_ELEM = 1024


def parse_command_lines(lines: object) -> list[list[str]]:
    """Parse command lines into argv vectors (shlex tokenization, no shell).

    Each non-blank line becomes one argv vector. Quoting is honoured (``echo "a
    b"`` → two tokens) but nothing is ever executed through a shell. Raises
    ValueError on a malformed line or an empty result.
    """
    if not isinstance(lines, list):
        raise ValueError("commands must be a list of command lines")
    commands: list[list[str]] = []
    for raw in lines:
        if not isinstance(raw, str):
            raise ValueError("each command must be a string")
        if not raw.strip():
            continue  # skip blank lines
        try:
            argv = shlex.split(raw)
        except ValueError as exc:
            raise ValueError(f"could not parse command {raw!r}: {exc}") from exc
        if not argv:
            continue
        if len(argv) > _MAX_ARGV:
            raise ValueError(f"command has too many tokens (max {_MAX_ARGV})")
        for elem in argv:
            if "\x00" in elem or len(elem) > _MAX_ELEM:
                raise ValueError("command token contains a null byte or is too long")
        commands.append(argv)
    if not commands:
        raise ValueError("at least one command is required")
    if len(commands) > _MAX_COMMANDS:
        raise ValueError(f"too many commands (max {_MAX_COMMANDS})")
    return commands


def lines_of(commands: list[list[str]]) -> list[str]:
    """Render stored argv vectors back to canonical command lines (for display)."""
    return [shlex.join(argv) for argv in commands]


async def list_all(session: AsyncSession) -> list[CustomAction]:
    result = await session.execute(select(CustomAction).order_by(CustomAction.name))
    return list(result.scalars())


async def get(session: AsyncSession, action_id: uuid.UUID) -> CustomAction | None:
    return await session.get(CustomAction, action_id)


async def get_by_name(session: AsyncSession, name: str) -> CustomAction | None:
    result = await session.execute(select(CustomAction).where(CustomAction.name == name))
    return result.scalar_one_or_none()


async def tag_ids_for(session: AsyncSession, action_id: uuid.UUID) -> list[uuid.UUID]:
    result = await session.execute(
        select(CustomActionTag.tag_id).where(CustomActionTag.action_id == action_id)
    )
    return list(result.scalars())


async def _set_tags(
    session: AsyncSession, action_id: uuid.UUID, tag_ids: Sequence[uuid.UUID]
) -> None:
    await session.execute(
        delete(CustomActionTag).where(CustomActionTag.action_id == action_id)
    )
    for tag_id in dict.fromkeys(tag_ids):  # dedupe, keep order
        session.add(CustomActionTag(action_id=action_id, tag_id=tag_id))


async def create(
    session: AsyncSession,
    *,
    name: str,
    description: str,
    lines: list[str],
    tag_ids: Sequence[uuid.UUID],
    created_by: str | None,
) -> CustomAction:
    action = CustomAction(
        name=name,
        description=description,
        commands=parse_command_lines(lines),
        created_by=created_by,
    )
    session.add(action)
    await session.flush()
    await _set_tags(session, action.id, tag_ids)
    await session.flush()
    return action


async def update(
    session: AsyncSession,
    action_id: uuid.UUID,
    *,
    description: str | None = None,
    lines: list[str] | None = None,
    enabled: bool | None = None,
    tag_ids: Sequence[uuid.UUID] | None = None,
) -> CustomAction | None:
    action = await session.get(CustomAction, action_id)
    if action is None:
        return None
    if description is not None:
        action.description = description
    if lines is not None:
        action.commands = parse_command_lines(lines)
    if enabled is not None:
        action.enabled = enabled
    if tag_ids is not None:
        await _set_tags(session, action_id, tag_ids)
    await session.flush()
    return action


async def remove(session: AsyncSession, action_id: uuid.UUID) -> bool:
    action = await session.get(CustomAction, action_id)
    if action is None:
        return False
    await session.delete(action)
    await session.flush()
    return True


async def vm_allowed(session: AsyncSession, action_id: uuid.UUID, vm_id: uuid.UUID) -> bool:
    """True if the VM carries at least one of the action's allowed tags.

    An action with no allowed tags runs nowhere (explicit-scope by design).
    """
    action_tags = set(await tag_ids_for(session, action_id))
    if not action_tags:
        return False
    vm_tags = set(
        (await session.execute(select(VMTag.tag_id).where(VMTag.vm_id == vm_id))).scalars()
    )
    return bool(action_tags & vm_tags)
