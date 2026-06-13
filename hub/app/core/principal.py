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
        """True only for human admin users.

        The MCP agent is deliberately NOT an admin: control-plane operations
        (approve/revoke VMs, toggle unrestricted mode, manage enrollment tokens,
        change fleet settings) require a human admin and are off-limits to a
        leaked service token.
        """
        return self.actor_type is ActorType.user and self.role is UserRole.admin

    @property
    def can_execute(self) -> bool:
        """Operator capability: run actions/commands, trigger updates, read audit.

        Granted to human admins and to the trusted automation agent (Hermes), but
        NOT to read-only users.
        """
        return self.actor_type is ActorType.agent or self.is_admin

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
        # The MCP façade authenticates with the service token. It is an operator,
        # not an admin: see is_admin / can_execute.
        return cls(actor_type=ActorType.agent, actor_id=name, role=UserRole.readonly)
