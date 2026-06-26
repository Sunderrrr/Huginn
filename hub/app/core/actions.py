"""Server-side catalog of whitelisted actions.

The hub validates that a requested action exists and that its parameters are
well-formed *before* a task is created. The worker holds the authoritative
name -> argv mapping (see ``worker/internal/whitelist``); the hub never ships a
shell string. Keeping the catalog here lets both the dashboard and the MCP façade
share one definition.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# A conservative identifier for things like systemd unit names: letters, digits,
# and a few separators. Prevents smuggling shell metacharacters through params.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")


class ActionError(ValueError):
    """Raised when an action name is unknown or its parameters are invalid."""


@dataclass(frozen=True)
class ActionParam:
    name: str
    required: bool = True
    pattern: re.Pattern[str] = _SAFE_NAME


@dataclass(frozen=True)
class ActionSpec:
    name: str
    description: str
    params: tuple[ActionParam, ...] = field(default_factory=tuple)


ACTION_CATALOG: dict[str, ActionSpec] = {
    "status": ActionSpec("status", "Report worker and host status."),
    "metrics": ActionSpec("metrics", "Report basic host metrics (cpu/mem/disk)."),
    "restart_service": ActionSpec(
        "restart_service",
        "Restart a systemd service by name.",
        params=(ActionParam("service"),),
    ),
    "list_upgradable_packages": ActionSpec(
        "list_upgradable_packages", "List packages with available upgrades."
    ),
    "apt_upgrade": ActionSpec("apt_upgrade", "Apply available apt package upgrades."),
    "update_worker": ActionSpec("update_worker", "Update the worker to the target version."),
}


def validate_action(name: str, params: dict[str, str] | None) -> dict[str, str]:
    """Validate an action request and return the normalized params.

    Raises ``ActionError`` for unknown actions, missing required params, unknown
    params, or params that fail their safety pattern.
    """
    spec = ACTION_CATALOG.get(name)
    if spec is None:
        raise ActionError(f"unknown action: {name!r}")

    params = params or {}
    allowed = {p.name for p in spec.params}
    extra = set(params) - allowed
    if extra:
        raise ActionError(f"unknown parameter(s) for {name!r}: {sorted(extra)}")

    normalized: dict[str, str] = {}
    for p in spec.params:
        if p.name not in params:
            if p.required:
                raise ActionError(f"missing required parameter {p.name!r} for {name!r}")
            continue
        value = params[p.name]
        if not isinstance(value, str) or not p.pattern.match(value):
            raise ActionError(f"invalid value for parameter {p.name!r}")
        normalized[p.name] = value
    return normalized
