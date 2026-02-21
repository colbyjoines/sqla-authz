"""Tests for explain_access()."""

from __future__ import annotations

import json

from sqla_authz._checks import can
from sqla_authz.explain import explain_access
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import MockActor, Post


class TestExplainAccess:
    def _make_post(self, *, id: int, is_published: bool, author_id: int) -> Post:
        return Post(id=id, title=f"Post {id}", is_published=is_published, author_id=author_id)

    def test_access_allowed_single_policy(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_only",
            description="Allow reading published posts",
        )

        actor = MockActor(id=1)
        post = self._make_post(id=1, is_published=True, author_id=2)
        result = explain_access(actor, "read", post, registry=registry)

        assert result.allowed is True
        assert result.action == "read"
        assert result.resource_type == "Post"
        assert result.deny_by_default is False
        assert len(result.policies) == 1
        assert result.policies[0].matched is True

    def test_access_denied_single_policy(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_only",
            description="Allow reading published posts",
        )

        actor = MockActor(id=1)
        post = self._make_post(id=2, is_published=False, author_id=2)
        result = explain_access(actor, "read", post, registry=registry)

        assert result.allowed is False
        assert len(result.policies) == 1
        assert result.policies[0].matched is False

    def test_access_multiple_policies_one_passes(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_only",
            description="Published posts are readable",
        )
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="Authors can read own posts",
        )

        actor = MockActor(id=2)
        # Unpublished but owned by actor
        post = self._make_post(id=2, is_published=False, author_id=2)
        result = explain_access(actor, "read", post, registry=registry)

        assert result.allowed is True
        assert len(result.policies) == 2
        matched = {p.name: p.matched for p in result.policies}
        assert matched["published_only"] is False
        assert matched["own_posts"] is True

    def test_access_multiple_policies_none_pass(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_only",
            description="Published posts",
        )
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="Own posts",
        )

        actor = MockActor(id=99)
        post = self._make_post(id=2, is_published=False, author_id=2)
        result = explain_access(actor, "read", post, registry=registry)

        assert result.allowed is False
        assert all(p.matched is False for p in result.policies)

    def test_access_no_policies_deny_by_default(self) -> None:
        registry = PolicyRegistry()
        actor = MockActor(id=1)
        post = self._make_post(id=1, is_published=True, author_id=1)
        result = explain_access(actor, "read", post, registry=registry)

        assert result.allowed is False
        assert result.deny_by_default is True
        assert len(result.policies) == 0

    def test_per_policy_matched_flags(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_only",
            description="Published",
        )
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="Own",
        )

        actor = MockActor(id=1)
        # Published AND owned -> both should match
        post = self._make_post(id=1, is_published=True, author_id=1)
        result = explain_access(actor, "read", post, registry=registry)

        assert result.allowed is True
        assert all(p.matched is True for p in result.policies)

    def test_result_matches_can(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_only",
            description="Published",
        )

        actor = MockActor(id=1)

        # Case 1: published post -> allowed
        pub_post = self._make_post(id=1, is_published=True, author_id=2)
        explain_result = explain_access(actor, "read", pub_post, registry=registry)
        can_result = can(actor, "read", pub_post, registry=registry)
        assert explain_result.allowed == can_result

        # Case 2: draft post -> denied
        draft_post = self._make_post(id=2, is_published=False, author_id=2)
        explain_result = explain_access(actor, "read", draft_post, registry=registry)
        can_result = can(actor, "read", draft_post, registry=registry)
        assert explain_result.allowed == can_result

    def test_to_dict_json_serializable(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_only",
            description="Published",
        )

        actor = MockActor(id=1)
        post = self._make_post(id=1, is_published=True, author_id=1)
        result = explain_access(actor, "read", post, registry=registry)

        d = result.to_dict()
        # Should not raise
        serialized = json.dumps(d)
        assert isinstance(serialized, str)
