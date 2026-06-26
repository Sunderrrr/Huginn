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
    def _has_identity(self) -> bool:
        """A real user is behind this principal — either a direct human session or
        an MCP agent acting on behalf of a user (a per-user MCP token)."""
        return self.actor_type is ActorType.user or self.user is not None

    @property
    def is_admin(self) -> bool:
        """True for an admin user, including via an on-behalf-of MCP token.

        The anonymous service-token agent (no carried user) is NOT admin:
        control-plane operations require a real admin identity.
        """
        return self._has_identity and self.role is UserRole.admin

    @property
    def is_operator(self) -> bool:
        """True for admin/operator users (incl. via an on-behalf-of MCP token)."""
        return self._has_identity and self.role in (UserRole.admin, UserRole.operator)

    @property
    def can_execute(self) -> bool:
        """Operator capability: run actions/commands, trigger updates, read audit.

        Granted to operators/admins (human or via an on-behalf-of MCP token) and
        to the anonymous service-token agent — but NOT to read-only users, even
        through MCP (an MCP token never grants more than its owner's real role).
        """
        if self.actor_type is ActorType.agent and self.user is None:
            return True  # anonymous service-token agent
        return self.is_operator

    @classmethod
    def from_user(cls, user: User) -> Principal:
        return cls(
            actor_type=ActorType.user,
            actor_id=str(user.id),
            role=user.role,
            user=user,
        )

    @classmethod
    def agent(cls, user: User | None = None, name: str = "hermes") -> Principal:
        """The MCP façade. With a user (per-user MCP token) it acts AS that user —
        actor_type stays ``agent`` so the audit shows "mcp", actor_id is the user's
        id (resolved to a username), and authorization uses the user's real role.
        Without a user (service-token-only calls) it's an operator, not an admin.
        """
        if user is not None:
            return cls(
                actor_type=ActorType.agent,
                actor_id=str(user.id),
                role=user.role,
                user=user,
            )
        return cls(actor_type=ActorType.agent, actor_id=name, role=UserRole.readonly)
