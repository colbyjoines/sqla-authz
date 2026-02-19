"""Tests for sqla_authz.testing._assertions — assertion helpers."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.testing._actors import MockActor
from sqla_authz.testing._assertions import (
    assert_authorized,
    assert_denied,
    assert_query_contains,
)
from tests.conftest import Post


class TestAssertAuthorized:
    """assert_authorized passes when authorized query returns rows."""

    def test_passes_when_rows_returned(self, session, sample_data) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="published posts",
        )
        actor = MockActor(id=1)
        stmt = select(Post)
        assert_authorized(session, stmt, actor, "read", registry=registry)

    def test_fails_when_zero_rows(self, session, sample_data) -> None:
        registry = PolicyRegistry()
        # No policy => deny by default => zero rows
        actor = MockActor(id=1)
        stmt = select(Post)
        with pytest.raises(AssertionError, match="expected authorized query to return rows"):
            assert_authorized(session, stmt, actor, "read", registry=registry)

    def test_checks_expected_count(self, session, sample_data) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="published posts",
        )
        actor = MockActor(id=1)
        stmt = select(Post)
        # sample_data has 2 published posts (post1, post3)
        assert_authorized(
            session,
            stmt,
            actor,
            "read",
            expected_count=2,
            registry=registry,
        )

    def test_expected_count_mismatch_raises(self, session, sample_data) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="published posts",
        )
        actor = MockActor(id=1)
        stmt = select(Post)
        with pytest.raises(AssertionError, match="expected 5 rows"):
            assert_authorized(
                session,
                stmt,
                actor,
                "read",
                expected_count=5,
                registry=registry,
            )


class TestAssertDenied:
    """assert_denied passes when authorized query returns zero rows."""

    def test_passes_when_zero_rows(self, session, sample_data) -> None:
        registry = PolicyRegistry()
        # No policy => deny by default
        actor = MockActor(id=1)
        stmt = select(Post)
        assert_denied(session, stmt, actor, "read", registry=registry)

    def test_fails_when_rows_returned(self, session, sample_data) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="published posts",
        )
        actor = MockActor(id=1)
        stmt = select(Post)
        with pytest.raises(AssertionError, match="expected zero rows"):
            assert_denied(session, stmt, actor, "read", registry=registry)


class TestAssertQueryContains:
    """assert_query_contains checks compiled SQL text."""

    def test_finds_text_in_sql(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="published posts",
        )
        actor = MockActor(id=1)
        stmt = select(Post)
        assert_query_contains(
            stmt,
            actor,
            "read",
            text="is_published",
            registry=registry,
        )

    def test_raises_when_text_not_found(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="published posts",
        )
        actor = MockActor(id=1)
        stmt = select(Post)
        with pytest.raises(AssertionError, match="not found in compiled SQL"):
            assert_query_contains(
                stmt,
                actor,
                "read",
                text="nonexistent_column",
                registry=registry,
            )
