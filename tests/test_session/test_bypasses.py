"""Tests for bypass handler functions directly."""

from __future__ import annotations

import logging
import warnings

import pytest
from sqlalchemy import create_engine, select, text, true
from sqlalchemy.orm import Session, sessionmaker

from sqla_authz._audit import log_bypass_event
from sqla_authz.config._config import AuthzConfig
from sqla_authz.exceptions import AuthzBypassError
from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.session._interceptor import install_interceptor
from tests.conftest import Base, MockActor, Organization, Post, User

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def bypass_engine():
    """Fresh engine for bypass tests."""
    eng = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def registry() -> PolicyRegistry:
    """Fresh registry per test."""
    return PolicyRegistry()


def _seed_data(sess: Session) -> None:
    """Seed test data into a session."""
    org = Organization(id=1, name="Acme Corp")
    sess.add(org)

    alice = User(id=1, name="Alice", role="admin", org_id=1)
    bob = User(id=2, name="Bob", role="editor", org_id=1)
    sess.add_all([alice, bob])

    post1 = Post(id=1, title="Public Post", is_published=True, author_id=1)
    post2 = Post(id=2, title="Draft Post", is_published=False, author_id=1)
    post3 = Post(id=3, title="Bob's Post", is_published=True, author_id=2)
    sess.add_all([post1, post2, post3])
    sess.flush()


def _seed_and_commit(engine) -> None:
    """Seed data in a separate session and commit."""
    plain_factory = sessionmaker(bind=engine)
    with plain_factory() as sess:
        _seed_data(sess)
        sess.commit()


# ---------------------------------------------------------------------------
# Tests: log_bypass_event
# ---------------------------------------------------------------------------


class TestLogBypassEvent:
    """Test the log_bypass_event audit function."""

    def test_logs_with_entity(self, caplog) -> None:
        """log_bypass_event logs entity name when provided."""
        with caplog.at_level(logging.WARNING, logger="sqla_authz.bypass"):
            log_bypass_event(
                bypass_type="column_load",
                entity=Post,
                statement_hint="SELECT * FROM posts",
                detail="session.get() bypassed authorization",
            )

        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert "BYPASS:column_load" in record.message
        assert "Post" in record.message
        assert "session.get() bypassed authorization" in record.message

    def test_logs_without_entity(self, caplog) -> None:
        """log_bypass_event logs <unknown> when entity is None."""
        with caplog.at_level(logging.WARNING, logger="sqla_authz.bypass"):
            log_bypass_event(
                bypass_type="no_entity",
                entity=None,
                detail="text query",
            )

        assert len(caplog.records) == 1
        assert "<unknown>" in caplog.records[0].message

    def test_truncates_statement_hint(self, caplog) -> None:
        """log_bypass_event truncates statement_hint to 200 chars."""
        long_hint = "x" * 500
        with caplog.at_level(logging.WARNING, logger="sqla_authz.bypass"):
            log_bypass_event(
                bypass_type="test",
                entity=Post,
                statement_hint=long_hint,
            )

        record = caplog.records[0]
        # The full 500-char hint should not appear, only first 200
        assert "x" * 201 not in record.message

    def test_uses_type_specific_logger(self, caplog) -> None:
        """log_bypass_event uses sqla_authz.bypass.<type> logger."""
        with caplog.at_level(logging.WARNING, logger="sqla_authz.bypass.column_load"):
            log_bypass_event(
                bypass_type="column_load",
                entity=Post,
                detail="test",
            )

        assert len(caplog.records) >= 1
        assert caplog.records[0].name == "sqla_authz.bypass.column_load"


# ---------------------------------------------------------------------------
# Tests: AuthzBypassError
# ---------------------------------------------------------------------------


class TestAuthzBypassError:
    """Test AuthzBypassError exception."""

    def test_inherits_from_authz_error(self) -> None:
        """AuthzBypassError should be a subclass of AuthzError."""
        from sqla_authz.exceptions import AuthzError

        assert issubclass(AuthzBypassError, AuthzError)

    def test_can_be_raised_and_caught(self) -> None:
        """AuthzBypassError can be raised and caught."""
        with pytest.raises(AuthzBypassError, match="test bypass"):
            raise AuthzBypassError("test bypass")

    def test_importable_from_package(self) -> None:
        """AuthzBypassError should be importable from sqla_authz."""
        from sqla_authz import AuthzBypassError as Imported

        assert Imported is AuthzBypassError


# ---------------------------------------------------------------------------
# Tests: End-to-end bypass integration
# ---------------------------------------------------------------------------


class TestBypassIntegration:
    """Integration tests verifying bypass handlers fire during real queries."""

    def test_normal_select_no_bypass(self, bypass_engine, registry) -> None:
        """Normal ORM SELECT should not trigger any bypass handler."""
        actor = MockActor(id=1)
        config = AuthzConfig(
            on_skip_authz="warn",
            on_text_query="warn",
            on_unprotected_get="warn",
        )

        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published",
            description="",
        )

        factory = sessionmaker(bind=bypass_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            _seed_data(sess)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                results = sess.execute(select(Post)).scalars().all()
                assert len(results) == 2
                assert all(p.is_published for p in results)
                # No bypass warnings — this was a normal ORM query
                bypass_warnings = [
                    w
                    for w in caught
                    if "bypass" in str(w.message).lower()
                    or "skip_authz" in str(w.message)
                    or "no ORM entities" in str(w.message)
                    or "Unprotected" in str(w.message)
                ]
                assert len(bypass_warnings) == 0

    def test_non_select_does_not_trigger_bypass(self, bypass_engine, registry) -> None:
        """INSERT/UPDATE/DELETE should not trigger bypass handlers."""
        from sqlalchemy import insert

        actor = MockActor(id=1)
        config = AuthzConfig(
            on_skip_authz="warn",
            on_text_query="raise",
            on_unprotected_get="raise",
        )

        registry.register(
            Post,
            "read",
            lambda a: true(),
            name="allow_all",
            description="",
        )

        factory = sessionmaker(bind=bypass_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            sess.execute(insert(User).values(id=1, name="Alice", role="admin"))
            sess.execute(insert(Post).values(id=99, title="Test", is_published=True, author_id=1))
            sess.flush()

    def test_multiple_bypass_types_in_one_session(
        self,
        bypass_engine,
        registry,
        caplog,
    ) -> None:
        """Multiple bypass types can fire in a single session."""
        actor = MockActor(id=1)
        config = AuthzConfig(
            on_skip_authz="log",
            on_text_query="warn",
            audit_bypasses=True,
        )

        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published",
            description="",
        )

        _seed_and_commit(bypass_engine)

        factory = sessionmaker(bind=bypass_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                with caplog.at_level(logging.INFO, logger="sqla_authz.bypass"):
                    # skip_authz bypass
                    sess.execute(select(Post).execution_options(skip_authz=True)).scalars().all()

                    # text query bypass
                    sess.execute(text("SELECT 1")).fetchall()

            # Verify skip_authz was logged
            assert any("skip_authz" in r.message for r in caplog.records)
            # Verify text query warning was emitted
            text_warnings = [w for w in caught if "no ORM entities" in str(w.message)]
            assert len(text_warnings) >= 1
