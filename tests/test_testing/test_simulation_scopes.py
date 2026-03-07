"""Tests for scope awareness in simulate_query()."""

from __future__ import annotations

from sqlalchemy import Integer, String, select, true
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.policy._scope import ScopeRegistration
from sqla_authz.testing._actors import MockActor
from sqla_authz.testing._simulation import simulate_query


# ---------------------------------------------------------------------------
# Test-local model
# ---------------------------------------------------------------------------


class SimScopeBase(DeclarativeBase):
    pass


class SimScopedPost(SimScopeBase):
    __tablename__ = "sim_scoped_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    org_id: Mapped[int] = mapped_column(Integer)
    is_published: Mapped[bool] = mapped_column(default=False)


class TestSimulateQueryScopes:
    def test_scopes_applied_populated(self) -> None:
        """scopes_applied is populated when scopes exist."""
        registry = PolicyRegistry()
        registry.register(
            SimScopedPost,
            "read",
            lambda actor: SimScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(SimScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        stmt = select(SimScopedPost)
        result = simulate_query(stmt, actor=actor, action="read", registry=registry)

        assert "SimScopedPost" in result.scopes_applied
        assert result.scopes_applied["SimScopedPost"] == ["tenant"]

    def test_no_scopes_empty_dict(self) -> None:
        """scopes_applied is empty when no scopes registered."""
        registry = PolicyRegistry()
        registry.register(
            SimScopedPost,
            "read",
            lambda actor: SimScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="",
        )

        actor = MockActor(id=1)
        stmt = select(SimScopedPost)
        result = simulate_query(stmt, actor=actor, action="read", registry=registry)

        assert result.scopes_applied == {}

    def test_multiple_scopes_listed(self) -> None:
        """Multiple scopes for a model are all listed."""
        registry = PolicyRegistry()
        registry.register(
            SimScopedPost,
            "read",
            lambda actor: true(),
            name="allow_all",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(SimScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))
        registry.register_scope(ScopeRegistration(
            applies_to=(SimScopedPost,),
            fn=lambda actor, Model: Model.is_published == True,  # noqa: E712
            name="published_scope",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        stmt = select(SimScopedPost)
        result = simulate_query(stmt, actor=actor, action="read", registry=registry)

        assert set(result.scopes_applied["SimScopedPost"]) == {"tenant", "published_scope"}

    def test_authorized_sql_includes_scope_filters(self) -> None:
        """The authorized SQL includes scope filters."""
        registry = PolicyRegistry()
        registry.register(
            SimScopedPost,
            "read",
            lambda actor: SimScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(SimScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        stmt = select(SimScopedPost)
        result = simulate_query(stmt, actor=actor, action="read", registry=registry)

        assert "org_id" in result.authorized_sql

    def test_str_includes_scopes(self) -> None:
        """__str__() mentions scopes."""
        registry = PolicyRegistry()
        registry.register(
            SimScopedPost,
            "read",
            lambda actor: true(),
            name="allow",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(SimScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        stmt = select(SimScopedPost)
        result = simulate_query(stmt, actor=actor, action="read", registry=registry)

        text = str(result)
        assert "Scopes:" in text
        assert "tenant" in text

    def test_backward_compatible_without_scopes(self) -> None:
        """SimulationResult without scopes still works (default empty dict)."""
        from sqla_authz.testing._simulation import SimulationResult

        result = SimulationResult(
            original_sql="SELECT 1",
            authorized_sql="SELECT 1 WHERE true",
            actor_repr="actor",
            action="read",
            policies_applied={"Post": ["p1"]},
        )
        assert result.scopes_applied == {}
        text = str(result)
        assert "Scopes:" not in text
