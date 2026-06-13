"""The authenticated principal acting on a request (a user or an agent)."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import ActorType, UserRole
from app.models.user import User


@dataclass(frozen=True)
class Principal:
    """Who is performing an action, for authorization and audit."""

    actor_type: ActorType
    actor_id: str
    role: UserRole
    user: User | None = None

    @property
    def is_admin(self) -> bool:
        return self.role is UserRole.admin

    @classmethod
    def from_user(cls, user: User) -> Principal:
        return cls(
            actor_type=ActorType.user,
            actor_id=str(user.id),
            role=user.role,
            user=user,
        )

    @classmethod
    def agent(cls, name: str = "hermes") -> Principal:
        # The MCP façade authenticates with the service token and acts as a
        # trusted agent with admin-equivalent rights.
        return cls(actor_type=ActorType.agent, actor_id=name, role=UserRole.admin)
