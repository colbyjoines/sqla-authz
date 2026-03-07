"""Tests for scope AND'ing in evaluate_policies()."""

from __future__ import annotations

from sqlalchemy import ColumnElement, Integer, String, select, true
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from sqla_authz.compiler._eval import eval_expression
from sqla_authz.compiler._expression import evaluate_policies
from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.policy._scope import ScopeRegistration

from tests.conftest import MockActor


# ---------------------------------------------------------------------------
# Test-local models with org_id for scope testing
# ---------------------------------------------------------------------------


class ScopeTestBase(DeclarativeBase):
    pass


class TenantPost(ScopeTestBase):
    __tablename__ = "scope_test_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    org_id: Mapped[int] = mapped_column(Integer)
    is_published: Mapped[bool] = mapped_column(default=False)
    deleted_at: Mapped[str | None] = mapped_column(String(50), nullable=True)


class TenantComment(ScopeTestBase):
    __tablename__ = "scope_test_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    body: Mapped[str] = mapped_column(String(500))
    org_id: Mapped[int] = mapped_column(Integer)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScopeComposition:
    """Test that scopes are AND'd with OR'd policies in evaluate_policies()."""

    def test_scope_ands_with_policy(self) -> None:
        """A scope is AND'd with the policy result."""
        registry = PolicyRegistry()
        registry.register(
            TenantPost, "read",
            lambda actor: TenantPost.is_published == True,  # noqa: E712
            name="published", description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(TenantPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        expr = evaluate_policies(registry, TenantPost, "read", actor)

        sql = str(expr.compile(compile_kwargs={"literal_binds": True}))
        assert "is_published" in sql
        assert "org_id" in sql

    def test_multiple_scopes_anded(self) -> None:
        """Multiple scopes on the same model are all AND'd."""
        registry = PolicyRegistry()
        registry.register(
            TenantPost, "read",
            lambda actor: true(),
            name="allow_all", description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(TenantPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))
        registry.register_scope(ScopeRegistration(
            applies_to=(TenantPost,),
            fn=lambda actor, Model: Model.deleted_at.is_(None),
            name="soft_delete", description="", actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        expr = evaluate_policies(registry, TenantPost, "read", actor)

        sql = str(expr.compile(compile_kwargs={"literal_binds": True}))
        assert "org_id" in sql
        assert "deleted_at" in sql

    def test_no_policies_returns_false_despite_scopes(self) -> None:
        """When no policies exist, false() is returned regardless of scopes."""
        registry = PolicyRegistry()
        registry.register_scope(ScopeRegistration(
            applies_to=(TenantPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        expr = evaluate_policies(registry, TenantPost, "read", actor)

        sql = str(expr.compile(compile_kwargs={"literal_binds": True}))
        # Should be false(), not the scope
        assert "org_id" not in sql

    def test_scope_with_action_restriction_applied(self) -> None:
        """A scope with actions=['read'] only applies to 'read'."""
        registry = PolicyRegistry()
        registry.register(
            TenantPost, "read",
            lambda actor: true(),
            name="allow", description="",
        )
        registry.register(
            TenantPost, "delete",
            lambda actor: true(),
            name="allow_del", description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(TenantPost,),
            fn=lambda actor, Model: Model.deleted_at.is_(None),
            name="soft_delete", description="",
            actions=("read",),
        ))

        actor = MockActor(id=1)

        # Read should have the scope
        read_expr = evaluate_policies(registry, TenantPost, "read", actor)
        read_sql = str(read_expr.compile(compile_kwargs={"literal_binds": True}))
        assert "deleted_at" in read_sql

        # Delete should NOT have the scope
        del_expr = evaluate_policies(registry, TenantPost, "delete", actor)
        del_sql = str(del_expr.compile(compile_kwargs={"literal_binds": True}))
        assert "deleted_at" not in del_sql

    def test_scope_bypass_via_true(self) -> None:
        """A scope returning true() effectively bypasses the scope (admin)."""
        registry = PolicyRegistry()
        registry.register(
            TenantPost, "read",
            lambda actor: TenantPost.is_published == True,  # noqa: E712
            name="published", description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(TenantPost,),
            fn=lambda actor, Model: true() if actor.role == "admin" else Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        admin = MockActor(id=1, role="admin", org_id=1)
        expr = evaluate_policies(registry, TenantPost, "read", admin)
        sql = str(expr.compile(compile_kwargs={"literal_binds": True}))
        assert "org_id" not in sql
        assert "is_published" in sql

    def test_scope_does_not_affect_unrelated_model(self) -> None:
        """A scope registered for Post doesn't affect Comment."""
        registry = PolicyRegistry()
        registry.register(
            TenantComment, "read",
            lambda actor: true(),
            name="allow", description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(TenantPost,),  # Only Post, not Comment
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        expr = evaluate_policies(registry, TenantComment, "read", actor)
        sql = str(expr.compile(compile_kwargs={"literal_binds": True}))
        assert "org_id" not in sql

    def test_multiple_policies_ored_then_scope_anded(self) -> None:
        """OR'd policies are grouped, then AND'd with scopes."""
        registry = PolicyRegistry()
        # Two policies OR'd
        registry.register(
            TenantPost, "read",
            lambda actor: TenantPost.is_published == True,  # noqa: E712
            name="published", description="",
        )
        registry.register(
            TenantPost, "read",
            lambda actor: TenantPost.id == actor.id,
            name="own_post", description="",
        )
        # One scope AND'd
        registry.register_scope(ScopeRegistration(
            applies_to=(TenantPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        expr = evaluate_policies(registry, TenantPost, "read", actor)
        sql = str(expr.compile(compile_kwargs={"literal_binds": True}))
        assert "is_published" in sql
        assert "org_id" in sql


class TestScopeWithInMemoryEval:
    """Test that scoped expressions work with the in-memory evaluator (can())."""

    def test_scope_evaluated_in_memory(self) -> None:
        """Scoped expressions are correctly evaluated by eval_expression()."""
        registry = PolicyRegistry()
        registry.register(
            TenantPost, "read",
            lambda actor: TenantPost.is_published == True,  # noqa: E712
            name="published", description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(TenantPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        expr = evaluate_policies(registry, TenantPost, "read", actor)

        # Matching post: published + correct org
        post_ok = TenantPost(id=1, title="t", org_id=42, is_published=True)
        assert eval_expression(expr, post_ok) is True

        # Wrong org
        post_wrong_org = TenantPost(id=2, title="t", org_id=99, is_published=True)
        assert eval_expression(expr, post_wrong_org) is False

        # Right org but not published
        post_draft = TenantPost(id=3, title="t", org_id=42, is_published=False)
        assert eval_expression(expr, post_draft) is False

    def test_scope_bypass_evaluated_in_memory(self) -> None:
        """Admin bypass (true()) works in in-memory evaluation."""
        registry = PolicyRegistry()
        registry.register(
            TenantPost, "read",
            lambda actor: TenantPost.is_published == True,  # noqa: E712
            name="published", description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(TenantPost,),
            fn=lambda actor, Model: true() if actor.role == "admin" else Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        admin = MockActor(id=1, role="admin", org_id=1)
        expr = evaluate_policies(registry, TenantPost, "read", admin)

        # Admin sees published post from any org
        post = TenantPost(id=1, title="t", org_id=999, is_published=True)
        assert eval_expression(expr, post) is True


class TestScopeWithAuthorizeQuery:
    """Test that scopes integrate with authorize_query()."""

    def test_authorize_query_includes_scope(self) -> None:
        """authorize_query produces SQL with scope filters."""
        from sqla_authz.compiler._query import authorize_query

        registry = PolicyRegistry()
        registry.register(
            TenantPost, "read",
            lambda actor: TenantPost.is_published == True,  # noqa: E712
            name="published", description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(TenantPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        stmt = select(TenantPost)
        result = authorize_query(stmt, actor=actor, action="read", registry=registry)

        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "is_published" in sql
        assert "org_id" in sql
