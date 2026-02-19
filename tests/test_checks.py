"""Tests for can() and authorize() point check functions."""

from __future__ import annotations

import sys

import pytest
from sqlalchemy import ColumnElement, false, true

from sqla_authz._checks import authorize, can
from sqla_authz.exceptions import AuthorizationDenied
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import MockActor, Post

# ---------------------------------------------------------------------------
# Helpers — register policies on a per-test registry
# ---------------------------------------------------------------------------


def _published_policy(actor: MockActor) -> ColumnElement[bool]:
    """Allow reading published posts."""
    return Post.is_published == True  # noqa: E712


def _author_policy(actor: MockActor) -> ColumnElement[bool]:
    """Allow reading own posts."""
    return Post.author_id == actor.id


def _published_or_author_policy(actor: MockActor) -> ColumnElement[bool]:
    """Allow published posts OR own posts."""
    return (Post.is_published == True) | (Post.author_id == actor.id)  # noqa: E712


def _always_allow(actor: MockActor) -> ColumnElement[bool]:
    return true()


def _always_deny(actor: MockActor) -> ColumnElement[bool]:
    return false()


# ---------------------------------------------------------------------------
# TestCan
# ---------------------------------------------------------------------------


class TestCan:
    """Tests for the can() function."""

    def test_returns_true_when_policy_allows(self, session, sample_data):
        """Published post should be readable when policy allows published."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _published_policy, name="published", description="")

        post1 = sample_data["posts"][0]  # published
        actor = MockActor(id=99)

        assert can(actor, "read", post1, registry=registry) is True

    def test_returns_false_when_policy_denies(self, session, sample_data):
        """Draft post should not be readable under published-only policy."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _published_policy, name="published", description="")

        post2 = sample_data["posts"][1]  # draft (is_published=False)
        actor = MockActor(id=99)

        assert can(actor, "read", post2, registry=registry) is False

    def test_returns_false_no_policy_registered(self, session, sample_data):
        """No policy registered → deny by default."""
        registry = PolicyRegistry()
        post1 = sample_data["posts"][0]
        actor = MockActor(id=1)

        assert can(actor, "read", post1, registry=registry) is False

    def test_with_actor_attribute_binding_match(self, session, sample_data):
        """Policy checks author_id == actor.id — matching actor."""
        registry = PolicyRegistry()
        registry.register(Post, "update", _author_policy, name="author", description="")

        post1 = sample_data["posts"][0]  # author_id=1
        actor = MockActor(id=1)

        assert can(actor, "update", post1, registry=registry) is True

    def test_with_actor_attribute_binding_no_match(self, session, sample_data):
        """Policy checks author_id == actor.id — non-matching actor."""
        registry = PolicyRegistry()
        registry.register(Post, "update", _author_policy, name="author", description="")

        post1 = sample_data["posts"][0]  # author_id=1
        actor = MockActor(id=999)

        assert can(actor, "update", post1, registry=registry) is False

    def test_with_or_conditions_published(self, session, sample_data):
        """OR policy: published post readable by anyone."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            _published_or_author_policy,
            name="pub_or_author",
            description="",
        )

        post1 = sample_data["posts"][0]  # published, author_id=1
        actor = MockActor(id=99)  # not the author

        assert can(actor, "read", post1, registry=registry) is True

    def test_with_or_conditions_author(self, session, sample_data):
        """OR policy: draft readable by author."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            _published_or_author_policy,
            name="pub_or_author",
            description="",
        )

        post2 = sample_data["posts"][1]  # draft, author_id=1
        actor = MockActor(id=1)  # author

        assert can(actor, "read", post2, registry=registry) is True

    def test_with_or_conditions_denied(self, session, sample_data):
        """OR policy: draft by other author → denied."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            _published_or_author_policy,
            name="pub_or_author",
            description="",
        )

        post2 = sample_data["posts"][1]  # draft, author_id=1
        actor = MockActor(id=99)  # not the author

        assert can(actor, "read", post2, registry=registry) is False

    def test_with_true_expression(self, session, sample_data):
        """Policy returning true() → always allowed."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _always_allow, name="allow_all", description="")

        post2 = sample_data["posts"][1]  # even a draft
        actor = MockActor(id=99)

        assert can(actor, "read", post2, registry=registry) is True

    def test_with_false_expression(self, session, sample_data):
        """Policy returning false() → always denied."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _always_deny, name="deny_all", description="")

        post1 = sample_data["posts"][0]  # even published
        actor = MockActor(id=1)

        assert can(actor, "read", post1, registry=registry) is False

    def test_with_custom_registry(self, session, sample_data):
        """Explicit registry parameter is used instead of global."""
        custom = PolicyRegistry()
        custom.register(Post, "read", _always_allow, name="allow_all", description="")

        empty = PolicyRegistry()

        post1 = sample_data["posts"][0]
        actor = MockActor(id=1)

        assert can(actor, "read", post1, registry=custom) is True
        assert can(actor, "read", post1, registry=empty) is False

    def test_multiple_policies_or_combined(self, session, sample_data):
        """Multiple policies for same key are OR'd — any match grants access."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _published_policy, name="published", description="")
        registry.register(Post, "read", _author_policy, name="author", description="")

        # Draft by actor → author policy matches
        post2 = sample_data["posts"][1]  # draft, author_id=1
        actor = MockActor(id=1)

        assert can(actor, "read", post2, registry=registry) is True

    def test_different_action_not_matched(self, session, sample_data):
        """Policy for 'read' doesn't apply to 'delete'."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _always_allow, name="allow_read", description="")

        post1 = sample_data["posts"][0]
        actor = MockActor(id=1)

        assert can(actor, "delete", post1, registry=registry) is False


# ---------------------------------------------------------------------------
# TestAuthorize
# ---------------------------------------------------------------------------


class TestAuthorize:
    """Tests for the authorize() function."""

    def test_passes_when_authorized(self, session, sample_data):
        """Should return None (no exception) when access is granted."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _published_policy, name="published", description="")

        post1 = sample_data["posts"][0]  # published
        actor = MockActor(id=99)

        result = authorize(actor, "read", post1, registry=registry)
        assert result is None

    def test_raises_when_denied(self, session, sample_data):
        """Should raise AuthorizationDenied when denied."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _published_policy, name="published", description="")

        post2 = sample_data["posts"][1]  # draft
        actor = MockActor(id=99)

        with pytest.raises(AuthorizationDenied):
            authorize(actor, "read", post2, registry=registry)

    def test_raises_with_custom_message(self, session, sample_data):
        """Custom message parameter should appear in exception."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _published_policy, name="published", description="")

        post2 = sample_data["posts"][1]  # draft
        actor = MockActor(id=99)

        with pytest.raises(AuthorizationDenied, match="Cannot view this post"):
            authorize(
                actor,
                "read",
                post2,
                registry=registry,
                message="Cannot view this post",
            )

    def test_exception_has_correct_attributes(self, session, sample_data):
        """Exception should carry actor, action, resource_type."""
        registry = PolicyRegistry()
        post2 = sample_data["posts"][1]
        actor = MockActor(id=42)

        with pytest.raises(AuthorizationDenied) as exc_info:
            authorize(actor, "read", post2, registry=registry)

        exc = exc_info.value
        assert exc.actor is actor
        assert exc.action == "read"
        assert exc.resource_type == "Post"

    def test_no_policy_raises_denied(self, session, sample_data):
        """No policy → AuthorizationDenied (deny by default)."""
        registry = PolicyRegistry()
        post1 = sample_data["posts"][0]
        actor = MockActor(id=1)

        with pytest.raises(AuthorizationDenied):
            authorize(actor, "read", post1, registry=registry)


# ---------------------------------------------------------------------------
# Edge case: Unicode and extreme actor IDs
# ---------------------------------------------------------------------------


class TestEdgeCaseActorIds:
    """Edge cases with unusual actor IDs."""

    def test_unicode_actor_id(self, session, sample_data):
        """Actor with unicode ID should work in policy evaluation."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _published_policy, name="published", description="")

        post1 = sample_data["posts"][0]  # published
        actor = MockActor(id="\u7528\u6237123")  # "用户123"

        assert can(actor, "read", post1, registry=registry) is True

    def test_unicode_actor_id_in_author_check(self, session, sample_data):
        """Unicode actor ID in author_id comparison should not crash."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _author_policy, name="author", description="")

        post1 = sample_data["posts"][0]  # author_id=1
        actor = MockActor(id="\u7528\u6237123")

        # Should not raise, just return False (string != int)
        assert can(actor, "read", post1, registry=registry) is False

    def test_very_large_actor_id(self, session, sample_data):
        """Actor with sys.maxsize ID should work without overflow."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _published_policy, name="published", description="")

        post1 = sample_data["posts"][0]  # published
        actor = MockActor(id=sys.maxsize)

        assert can(actor, "read", post1, registry=registry) is True

    def test_very_large_actor_id_in_author_check(self, session, sample_data):
        """Large actor ID in comparison should work for values within DB range."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _author_policy, name="author", description="")

        post1 = sample_data["posts"][0]  # author_id=1
        # Use a large value within SQLite INTEGER range (2^63 - 1)
        actor = MockActor(id=2**63 - 1)

        assert can(actor, "read", post1, registry=registry) is False

    def test_zero_actor_id(self, session, sample_data):
        """Actor with id=0 should not be confused with falsy values."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _published_policy, name="published", description="")

        post1 = sample_data["posts"][0]  # published
        actor = MockActor(id=0)

        assert can(actor, "read", post1, registry=registry) is True

    def test_empty_string_actor_id(self, session, sample_data):
        """Actor with empty string ID should work."""
        registry = PolicyRegistry()
        registry.register(Post, "read", _published_policy, name="published", description="")

        post1 = sample_data["posts"][0]  # published
        actor = MockActor(id="")

        assert can(actor, "read", post1, registry=registry) is True
