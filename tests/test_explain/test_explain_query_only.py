"""Tests for query_only flag in explain_access() output."""

from __future__ import annotations

from sqlalchemy import ColumnElement

from sqla_authz.explain._access import explain_access
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import MockActor, Post


def _published_policy(actor: MockActor) -> ColumnElement[bool]:
    return Post.is_published == True  # noqa: E712


class TestExplainAccessQueryOnly:
    """Tests for query_only flag in explain_access output."""

    def test_shows_query_only_flag(self, session, sample_data):
        """explain_access() output shows query_only in AccessPolicyEvaluation."""
        registry = PolicyRegistry()
        registry.register(
            Post, "read", _published_policy,
            name="published", description="Published posts", query_only=True,
        )

        post = sample_data["posts"][0]  # published
        actor = MockActor(id=1)

        result = explain_access(actor, "read", post, registry=registry)
        assert len(result.policies) == 1
        assert result.policies[0].query_only is True

    def test_query_only_policy_still_evaluates(self, session, sample_data):
        """explain_access() can evaluate query_only policies via SQLite."""
        registry = PolicyRegistry()
        registry.register(
            Post, "read", _published_policy,
            name="published", description="Published posts", query_only=True,
        )

        post = sample_data["posts"][0]  # published
        actor = MockActor(id=1)

        result = explain_access(actor, "read", post, registry=registry)
        # SQLite can evaluate this -- it should match
        assert result.policies[0].matched is True
        assert result.allowed is True

    def test_query_only_in_str_output(self, session, sample_data):
        """String output includes [query-only] prefix."""
        registry = PolicyRegistry()
        registry.register(
            Post, "read", _published_policy,
            name="published", description="Published posts", query_only=True,
        )

        post = sample_data["posts"][0]
        actor = MockActor(id=1)

        result = explain_access(actor, "read", post, registry=registry)
        output = str(result)
        assert "[query-only]" in output

    def test_non_query_only_no_prefix(self, session, sample_data):
        """Non-query-only policies don't get [query-only] prefix."""
        registry = PolicyRegistry()
        registry.register(
            Post, "read", _published_policy,
            name="published", description="Published posts",
        )

        post = sample_data["posts"][0]
        actor = MockActor(id=1)

        result = explain_access(actor, "read", post, registry=registry)
        output = str(result)
        assert "[query-only]" not in output
        assert result.policies[0].query_only is False

    def test_query_only_in_to_dict(self, session, sample_data):
        """to_dict() includes query_only when True."""
        registry = PolicyRegistry()
        registry.register(
            Post, "read", _published_policy,
            name="published", description="Published posts", query_only=True,
        )

        post = sample_data["posts"][0]
        actor = MockActor(id=1)

        result = explain_access(actor, "read", post, registry=registry)
        d = result.to_dict()
        assert d["policies"][0]["query_only"] is True

    def test_non_query_only_not_in_to_dict(self, session, sample_data):
        """to_dict() omits query_only when False (keeps output clean)."""
        registry = PolicyRegistry()
        registry.register(
            Post, "read", _published_policy,
            name="published", description="Published posts",
        )

        post = sample_data["posts"][0]
        actor = MockActor(id=1)

        result = explain_access(actor, "read", post, registry=registry)
        d = result.to_dict()
        assert "query_only" not in d["policies"][0]
