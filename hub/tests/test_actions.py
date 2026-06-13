"""Whitelist action catalog validation."""

from __future__ import annotations

import pytest

from app.core.actions import ACTION_CATALOG, ActionError, validate_action


def test_known_action_no_params() -> None:
    assert validate_action("status", None) == {}
    assert validate_action("metrics", {}) == {}


def test_unknown_action_rejected() -> None:
    with pytest.raises(ActionError):
        validate_action("rm_rf_slash", None)


def test_restart_service_requires_service_param() -> None:
    with pytest.raises(ActionError):
        validate_action("restart_service", {})
    assert validate_action("restart_service", {"service": "nginx"}) == {"service": "nginx"}


def test_param_injection_attempts_rejected() -> None:
    for evil in ["nginx; rm -rf /", "a b", "$(reboot)", "x`id`", "../../etc", "a|b", ""]:
        with pytest.raises(ActionError):
            validate_action("restart_service", {"service": evil})


def test_unknown_param_rejected() -> None:
    with pytest.raises(ActionError):
        validate_action("status", {"service": "nginx"})


def test_all_catalog_entries_have_consistent_names() -> None:
    for name, spec in ACTION_CATALOG.items():
        assert name == spec.name
