"""Tests for query_only policy support in can()/authorize()."""

from __future__ import annotations

import pytest
from sqlalchemy import ColumnElement, func, select

from sqla_authz._checks import authorize, can
from sqla_authz.compiler._query import authorize_query
from sqla_authz.exceptions import QueryOnlyPolicyError
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import MockActor, Post

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _published_policy(actor: MockActor) -> ColumnElement[bool]:
    return Post.is_published == True  # noqa: E712


def _query_only_policy(actor: MockActor) -> ColumnElement[bool]:
    """Uses func.lower() which is unsupported in point checks."""
    return func.lower(Post.title) == "public post"


# ---------------------------------------------------------------------------
# TestCanQueryOnly
# ---------------------------------------------------------------------------


class TestCanQueryOnly:
    """Tests for can() with query_only policies."""

    def test_can_raises_on_query_only_policy(self, session, sample_data):
        """can() raises QueryOnlyPolicyError for query_only=True policies."""
        registry = PolicyRegistry()
        registry.register(
            Post, "read", _query_only_policy,
            name="complex_read", description="", query_only=True,
        )

        post = sample_data["posts"][0]
        actor = MockActor(id=1)

        with pytest.raises(QueryOnlyPolicyError):
            can(actor, "read", post, registry=registry)

    def test_can_works_with_non_query_only(self, session, sample_data):
        """can() works normally when query_only=False (default)."""
        registry = PolicyRegistry()
        registry.register(
            Post, "read", _published_policy,
            name="published", description="",
        )

        post = sample_data["posts"][0]  # published
        actor = MockActor(id=1)

        assert can(actor, "read", post, registry=registry) is True

    def test_mixed_policies_raises_if_any_query_only(self, session, sample_data):
        """If any policy for (model, action) is query-only, can() raises."""
        registry = PolicyRegistry()
        registry.register(
            Post, "read", _published_policy,
            name="published", description="",
        )
        registry.register(
            Post, "read", _query_only_policy,
            name="complex_read", description="", query_only=True,
        )

        post = sample_data["posts"][0]
        actor = MockActor(id=1)

        with pytest.raises(QueryOnlyPolicyError) as exc_info:
            can(actor, "read", post, registry=registry)

        # Only the query-only policy name should appear
        assert exc_info.value.query_only_policies == ["complex_read"]

    def test_can_with_func_without_query_only_silently_fails(self, session, sample_data):
        """Without query_only, func.lower() silently returns False."""
        registry = PolicyRegistry()
        registry.register(
            Post, "read", _query_only_policy,
            name="complex_read", description="",  # query_only=False (default)
        )

        post = sample_data["posts"][0]
        actor = MockActor(id=1)

        # func.lower() can't be evaluated in-memory -- silently returns False
        assert can(actor, "read", post, registry=registry) is False


# ---------------------------------------------------------------------------
# TestAuthorizeQueryOnly
# ---------------------------------------------------------------------------


class TestAuthorizeQueryOnly:
    """Tests for authorize() with query_only policies."""

    def test_authorize_raises_query_only_error(self, session, sample_data):
        """authorize() propagates QueryOnlyPolicyError from can()."""
        registry = PolicyRegistry()
        registry.register(
            Post, "read", _query_only_policy,
            name="complex_read", description="", query_only=True,
        )

        post = sample_data["posts"][0]
        actor = MockActor(id=1)

        with pytest.raises(QueryOnlyPolicyError):
            authorize(actor, "read", post, registry=registry)


# ---------------------------------------------------------------------------
# TestQueryOnlyPolicyError
# ---------------------------------------------------------------------------


class TestQueryOnlyPolicyError:
    """Tests for the QueryOnlyPolicyError exception."""

    def test_error_message_format(self):
        """Error message includes resource type, action, and policy names."""
        exc = QueryOnlyPolicyError(
            resource_type="Post",
            action="read",
            query_only_policies=["complex_read", "another"],
        )
        msg = str(exc)
        assert "Post" in msg
        assert "'read'" in msg
        assert "complex_read" in msg
        assert "another" in msg
        assert "authorize_query()" in msg

    def test_error_attributes(self):
        """Exception carries structured attributes."""
        exc = QueryOnlyPolicyError(
            resource_type="Post",
            action="read",
            query_only_policies=["p1"],
        )
        assert exc.resource_type == "Post"
        assert exc.action == "read"
        assert exc.query_only_policies == ["p1"]

    def test_is_authz_error_subclass(self):
        """QueryOnlyPolicyError is an AuthzError."""
        from sqla_authz.exceptions import AuthzError

        exc = QueryOnlyPolicyError(
            resource_type="Post",
            action="read",
            query_only_policies=["p1"],
        )
        assert isinstance(exc, AuthzError)


# ---------------------------------------------------------------------------
# TestAuthorizeQueryUnaffected
# ---------------------------------------------------------------------------


class TestAuthorizeQueryUnaffected:
    """authorize_query() should work fine with query-only policies."""

    def test_authorize_query_works_with_query_only_policy(self):
        """authorize_query() doesn't check query_only -- it works for all policies."""
        registry = PolicyRegistry()
        registry.register(
            Post, "read", _query_only_policy,
            name="complex_read", description="", query_only=True,
        )

        actor = MockActor(id=1)
        stmt = select(Post)
        # Should not raise
        result = authorize_query(stmt, actor=actor, action="read", registry=registry)
        assert result is not None
