"""Tests for AuthorizationContext."""

from __future__ import annotations

import pytest

from sqla_authz.config._config import AuthzConfig
from sqla_authz.session._context import AuthorizationContext
from tests.conftest import MockActor


class TestAuthorizationContext:
    """Test AuthorizationContext creation and immutability."""

    def test_creation_with_required_fields(self) -> None:
        actor = MockActor(id=1)
        config = AuthzConfig()
        ctx = AuthorizationContext(actor=actor, action="read", config=config)
        assert ctx.actor is actor
        assert ctx.action == "read"
        assert ctx.config is config

    def test_frozen_cannot_set_actor(self) -> None:
        actor = MockActor(id=1)
        ctx = AuthorizationContext(actor=actor, action="read", config=AuthzConfig())
        with pytest.raises(AttributeError):
            ctx.actor = MockActor(id=2)  # type: ignore[misc]

    def test_frozen_cannot_set_action(self) -> None:
        actor = MockActor(id=1)
        ctx = AuthorizationContext(actor=actor, action="read", config=AuthzConfig())
        with pytest.raises(AttributeError):
            ctx.action = "write"  # type: ignore[misc]

    def test_frozen_cannot_set_config(self) -> None:
        actor = MockActor(id=1)
        ctx = AuthorizationContext(actor=actor, action="read", config=AuthzConfig())
        with pytest.raises(AttributeError):
            ctx.config = AuthzConfig()  # type: ignore[misc]

    def test_uses_default_config_values(self) -> None:
        actor = MockActor(id=1)
        ctx = AuthorizationContext(actor=actor, action="read", config=AuthzConfig())
        assert ctx.config.on_missing_policy == "deny"
        assert ctx.config.default_action == "read"

    def test_uses_custom_config(self) -> None:
        actor = MockActor(id=1)
        config = AuthzConfig(on_missing_policy="raise", default_action="update")
        ctx = AuthorizationContext(actor=actor, action="update", config=config)
        assert ctx.config.on_missing_policy == "raise"
        assert ctx.config.default_action == "update"
