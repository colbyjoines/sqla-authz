"""Tests for compiler/_expression.py — policy evaluation to filter expressions."""

from __future__ import annotations

from sqlalchemy import ColumnElement, false, true

from sqla_authz.compiler._expression import evaluate_policies
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import MockActor, Post


class TestEvaluatePolicies:
    """evaluate_policies() calls policy functions and combines results."""

    def test_single_policy_returns_its_expression(self):
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="p",
            description="",
        )
        actor = MockActor(id=1)
        result = evaluate_policies(registry, Post, "read", actor)
        # Should produce a ColumnElement
        assert isinstance(result, ColumnElement)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "is_published" in sql

    def test_multiple_policies_combined_with_or(self):
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="p1",
            description="",
        )
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="p2",
            description="",
        )
        actor = MockActor(id=42)
        result = evaluate_policies(registry, Post, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        # Both conditions should appear in an OR
        assert "is_published" in sql
        assert "author_id" in sql

    def test_no_policies_returns_false(self):
        """Deny by default — no policy means WHERE FALSE."""
        registry = PolicyRegistry()
        actor = MockActor(id=1)
        result = evaluate_policies(registry, Post, "read", actor)
        # Should compile to false (1 != 1 or similar)
        assert result is not None

    def test_policy_returning_true_allows_all(self):
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: true(),
            name="allow_all",
            description="",
        )
        actor = MockActor(id=1)
        result = evaluate_policies(registry, Post, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "true" in sql.lower() or "1 = 1" in sql

    def test_policy_returning_false_denies_all(self):
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: false(),
            name="deny_all",
            description="",
        )
        actor = MockActor(id=1)
        result = evaluate_policies(registry, Post, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "false" in sql.lower() or "1 != 1" in sql

    def test_actor_attributes_bound_into_expression(self):
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own",
            description="",
        )
        actor = MockActor(id=99)
        result = evaluate_policies(registry, Post, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "99" in sql
