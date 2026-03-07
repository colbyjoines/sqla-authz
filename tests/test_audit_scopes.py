"""Tests for scope names in audit logging."""

from __future__ import annotations

import logging

from sqlalchemy import Integer, String, true
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from sqla_authz.compiler._expression import evaluate_policies
from sqla_authz.config._config import _reset_global_config, configure
from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.policy._scope import ScopeRegistration
from tests.conftest import MockActor


# ---------------------------------------------------------------------------
# Test-local model
# ---------------------------------------------------------------------------


class AuditScopeBase(DeclarativeBase):
    pass


class AuditScopedPost(AuditScopeBase):
    __tablename__ = "audit_scoped_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    org_id: Mapped[int] = mapped_column(Integer)


class TestAuditScopeLogging:
    def setup_method(self) -> None:
        _reset_global_config()

    def teardown_method(self) -> None:
        _reset_global_config()

    def test_scope_names_logged_at_debug(self, caplog) -> None:
        """Scope names appear in DEBUG log when scopes are applied."""
        configure(log_policy_decisions=True)
        registry = PolicyRegistry()
        registry.register(
            AuditScopedPost,
            "read",
            lambda actor: true(),
            name="allow_all",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(AuditScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant_scope",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        with caplog.at_level(logging.DEBUG, logger="sqla_authz"):
            evaluate_policies(registry, AuditScopedPost, "read", actor)

        debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
        scope_records = [r for r in debug_records if "Scopes applied" in r.message]
        assert len(scope_records) == 1
        assert "tenant_scope" in scope_records[0].message

    def test_no_scope_log_when_no_scopes(self, caplog) -> None:
        """No scope log line when no scopes are registered."""
        configure(log_policy_decisions=True)
        registry = PolicyRegistry()
        registry.register(
            AuditScopedPost,
            "read",
            lambda actor: true(),
            name="allow_all",
            description="",
        )

        actor = MockActor(id=1)
        with caplog.at_level(logging.DEBUG, logger="sqla_authz"):
            evaluate_policies(registry, AuditScopedPost, "read", actor)

        debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
        scope_records = [r for r in debug_records if "Scopes applied" in r.message]
        assert len(scope_records) == 0

    def test_multiple_scopes_logged(self, caplog) -> None:
        """Multiple scope names appear in a single log line."""
        configure(log_policy_decisions=True)
        registry = PolicyRegistry()
        registry.register(
            AuditScopedPost,
            "read",
            lambda actor: true(),
            name="allow_all",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(AuditScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))
        registry.register_scope(ScopeRegistration(
            applies_to=(AuditScopedPost,),
            fn=lambda actor, Model: true(),
            name="region",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        with caplog.at_level(logging.DEBUG, logger="sqla_authz"):
            evaluate_policies(registry, AuditScopedPost, "read", actor)

        debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
        scope_records = [r for r in debug_records if "Scopes applied" in r.message]
        assert len(scope_records) == 1
        msg = scope_records[0].message
        assert "tenant" in msg
        assert "region" in msg

    def test_scope_log_disabled_when_logging_off(self, caplog) -> None:
        """No scope logging when log_policy_decisions is False."""
        # Default config has logging disabled
        registry = PolicyRegistry()
        registry.register(
            AuditScopedPost,
            "read",
            lambda actor: true(),
            name="allow_all",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(AuditScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        with caplog.at_level(logging.DEBUG, logger="sqla_authz"):
            evaluate_policies(registry, AuditScopedPost, "read", actor)

        assert len(caplog.records) == 0
