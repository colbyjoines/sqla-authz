"""Tests for explain_query()."""

from __future__ import annotations

from sqlalchemy import select

from sqla_authz.explain import explain_query
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import MockActor, Post, User


class TestExplainQuery:
    def test_single_entity_single_policy(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_only",
            description="Allow reading published posts",
        )

        actor = MockActor(id=1)
        stmt = select(Post)
        result = explain_query(stmt, actor=actor, action="read", registry=registry)

        assert result.action == "read"
        assert len(result.entities) == 1

        entity = result.entities[0]
        assert entity.entity_name == "Post"
        assert entity.policies_found == 1
        assert entity.deny_by_default is False
        assert len(entity.policies) == 1
        assert entity.policies[0].name == "published_only"

    def test_single_entity_multiple_policies(self) -> None:
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

        actor = MockActor(id=1)
        stmt = select(Post)
        result = explain_query(stmt, actor=actor, action="read", registry=registry)

        entity = result.entities[0]
        assert entity.policies_found == 2
        assert len(entity.policies) == 2
        names = {p.name for p in entity.policies}
        assert names == {"published_only", "own_posts"}
        # Combined SQL should reflect OR combination
        assert entity.combined_filter_sql

    def test_no_policies_deny_by_default(self) -> None:
        registry = PolicyRegistry()
        actor = MockActor(id=1)
        stmt = select(Post)
        result = explain_query(stmt, actor=actor, action="read", registry=registry)

        assert result.has_deny_by_default is True
        assert len(result.entities) == 1
        entity = result.entities[0]
        assert entity.deny_by_default is True
        assert entity.policies_found == 0
        assert len(entity.policies) == 0

    def test_custom_registry(self) -> None:
        custom = PolicyRegistry()
        custom.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="custom_policy",
            description="Custom registry policy",
        )

        actor = MockActor(id=1)
        stmt = select(Post)
        result = explain_query(stmt, actor=actor, action="read", registry=custom)
        assert result.entities[0].policies[0].name == "custom_policy"

    def test_compiled_sql_contains_literal_binds(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="Own posts",
        )

        actor = MockActor(id=42)
        stmt = select(Post)
        result = explain_query(stmt, actor=actor, action="read", registry=registry)

        entity = result.entities[0]
        # Should contain the literal value 42, not :param_1
        assert "42" in entity.policies[0].filter_sql
        assert ":param" not in entity.policies[0].filter_sql
        # Also check the authorized SQL
        assert ":param" not in result.authorized_sql

    def test_has_deny_by_default_flag(self) -> None:
        registry = PolicyRegistry()
        # Register policy for Post but not User
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="p1",
            description="d1",
        )

        actor = MockActor(id=1)
        stmt = select(Post, User)
        result = explain_query(stmt, actor=actor, action="read", registry=registry)

        # User has no policy -> deny_by_default
        assert result.has_deny_by_default is True
        user_entity = [e for e in result.entities if e.entity_name == "User"][0]
        assert user_entity.deny_by_default is True
        post_entity = [e for e in result.entities if e.entity_name == "Post"][0]
        assert post_entity.deny_by_default is False
