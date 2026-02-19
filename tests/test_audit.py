"""Tests for audit logging."""

from __future__ import annotations

import logging

import pytest

from sqla_authz.compiler._expression import evaluate_policies
from sqla_authz.config._config import (
    AuthzConfig,
    _reset_global_config,
    configure,
    get_global_config,
)
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import MockActor, Post


class TestAuditLogging:
    """Tests for audit log output from policy evaluation."""

    def setup_method(self) -> None:
        _reset_global_config()

    def teardown_method(self) -> None:
        _reset_global_config()

    def test_logging_disabled_by_default(self, caplog: pytest.LogCaptureFixture) -> None:
        """No log output when log_policy_decisions is False (default)."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published",
            description="",
        )
        actor = MockActor(id=1)

        with caplog.at_level(logging.DEBUG, logger="sqla_authz"):
            evaluate_policies(registry, Post, "read", actor)

        assert len(caplog.records) == 0

    def test_info_level_summary(self, caplog: pytest.LogCaptureFixture) -> None:
        """INFO level logs entity, action, policy count."""
        configure(log_policy_decisions=True)
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published",
            description="",
        )
        actor = MockActor(id=1)

        with caplog.at_level(logging.INFO, logger="sqla_authz"):
            evaluate_policies(registry, Post, "read", actor)

        info_records = [r for r in caplog.records if r.levelno == logging.INFO]
        assert len(info_records) == 1
        msg = info_records[0].message
        assert "Post" in msg
        assert "read" in msg
        assert "1 policy" in msg

    def test_debug_level_details(self, caplog: pytest.LogCaptureFixture) -> None:
        """DEBUG level logs which policies matched and filter expression."""
        configure(log_policy_decisions=True)
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_posts",
            description="",
        )
        actor = MockActor(id=1)

        with caplog.at_level(logging.DEBUG, logger="sqla_authz"):
            evaluate_policies(registry, Post, "read", actor)

        debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
        assert len(debug_records) == 1
        msg = debug_records[0].message
        assert "published_posts" in msg
        assert "Post" in msg

    def test_warning_on_no_policy(self, caplog: pytest.LogCaptureFixture) -> None:
        """WARNING level when no policy found (deny-by-default triggered)."""
        configure(log_policy_decisions=True)
        registry = PolicyRegistry()
        actor = MockActor(id=1)

        with caplog.at_level(logging.WARNING, logger="sqla_authz"):
            evaluate_policies(registry, Post, "read", actor)

        warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warning_records) == 1
        msg = warning_records[0].message
        assert "No policy" in msg
        assert "Post" in msg
        assert "read" in msg

    def test_no_overhead_when_disabled(self) -> None:
        """When logging disabled, no string formatting occurs."""
        # Ensure default config (logging disabled)
        config = get_global_config()
        assert config.log_policy_decisions is False

        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published",
            description="",
        )
        actor = MockActor(id=1)

        # This should work without any logging overhead.
        # We verify by checking that the _audit module is not imported
        # when logging is disabled (lazy import pattern).
        import sys

        # Remove _audit from sys.modules if previously imported
        sys.modules.pop("sqla_authz._audit", None)

        evaluate_policies(registry, Post, "read", actor)

        # _audit should not have been imported since logging is disabled
        assert "sqla_authz._audit" not in sys.modules

    def test_multiple_policies_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """Multiple policies are logged correctly."""
        configure(log_policy_decisions=True)
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published",
            description="",
        )
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="",
        )
        actor = MockActor(id=1)

        with caplog.at_level(logging.DEBUG, logger="sqla_authz"):
            evaluate_policies(registry, Post, "read", actor)

        info_records = [r for r in caplog.records if r.levelno == logging.INFO]
        assert len(info_records) == 1
        assert "2 policy" in info_records[0].message

        debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
        assert len(debug_records) == 1
        assert "published" in debug_records[0].message
        assert "own_posts" in debug_records[0].message


class TestAuditConfig:
    """Tests for log_policy_decisions configuration field."""

    def setup_method(self) -> None:
        _reset_global_config()

    def teardown_method(self) -> None:
        _reset_global_config()

    def test_log_policy_decisions_default_false(self) -> None:
        """AuthzConfig defaults log_policy_decisions to False."""
        config = AuthzConfig()
        assert config.log_policy_decisions is False

    def test_merge_preserves_log_setting(self) -> None:
        """merge() handles log_policy_decisions field."""
        config = AuthzConfig(log_policy_decisions=True)
        merged = config.merge(default_action="update")
        assert merged.log_policy_decisions is True

    def test_merge_overrides_log_setting(self) -> None:
        """merge() can override log_policy_decisions."""
        config = AuthzConfig(log_policy_decisions=False)
        merged = config.merge(log_policy_decisions=True)
        assert merged.log_policy_decisions is True

    def test_merge_none_does_not_override_log_setting(self) -> None:
        """merge() with None log_policy_decisions preserves existing."""
        config = AuthzConfig(log_policy_decisions=True)
        merged = config.merge(log_policy_decisions=None)
        assert merged.log_policy_decisions is True

    def test_configure_enables_logging(self) -> None:
        """configure(log_policy_decisions=True) enables audit logging."""
        configure(log_policy_decisions=True)
        config = get_global_config()
        assert config.log_policy_decisions is True

    def test_configure_preserves_other_settings(self) -> None:
        """configure(log_policy_decisions=True) doesn't reset other fields."""
        configure(on_missing_policy="raise")
        configure(log_policy_decisions=True)
        config = get_global_config()
        assert config.on_missing_policy == "raise"
        assert config.log_policy_decisions is True

    def test_frozen_log_policy_decisions(self) -> None:
        """log_policy_decisions cannot be set after creation."""
        config = AuthzConfig(log_policy_decisions=True)
        with pytest.raises(AttributeError):
            config.log_policy_decisions = False  # type: ignore[misc]
