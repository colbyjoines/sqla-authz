"""Pytest fixtures for testing sqla-authz policies."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest

from sqla_authz.policy._registry import PolicyRegistry

__all__ = ["authz_registry", "authz_config", "authz_context"]


@pytest.fixture()
def authz_registry() -> Generator[PolicyRegistry, None, None]:
    """Provide a fresh, isolated ``PolicyRegistry`` for each test.

    The registry is created empty and is not shared with the global
    default registry.

    Example::

        def test_my_policy(authz_registry):
            authz_registry.register(Post, "read", my_fn, name="p", description="")
            assert authz_registry.has_policy(Post, "read")
    """
    yield PolicyRegistry()


@pytest.fixture()
def authz_config() -> dict[str, Any]:
    """Provide a default authorization config for testing.

    Returns a simple dict with default settings. Will be updated to
    return an ``AuthzConfig`` instance when the config module is ready.

    Example::

        def test_with_config(authz_config):
            assert authz_config["on_missing_policy"] == "deny"
    """
    try:
        from sqla_authz.config._config import AuthzConfig

        return AuthzConfig()  # type: ignore[return-value]
    except ImportError:
        return {"on_missing_policy": "deny", "default_action": "read"}


@pytest.fixture()
def authz_context() -> None:
    """Provide an ``AuthorizationContext`` fixture.

    Returns ``None`` until the session module is available.
    Will be updated when session interception is implemented.
    """
    return None
