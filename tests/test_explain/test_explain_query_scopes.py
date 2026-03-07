"""Tests for scope awareness in explain_query()."""

from __future__ import annotations

from sqlalchemy import Integer, String, select, true
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from sqla_authz.compiler._query import authorize_query
from sqla_authz.explain import explain_query
from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.policy._scope import ScopeRegistration
from tests.conftest import MockActor


# ---------------------------------------------------------------------------
# Test-local model with org_id for scope testing
# ---------------------------------------------------------------------------


class ScopeQueryBase(DeclarativeBase):
    pass


class QueryScopedPost(ScopeQueryBase):
    __tablename__ = "query_scoped_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    org_id: Mapped[int] = mapped_column(Integer)
    is_published: Mapped[bool] = mapped_column(default=False)


class TestExplainQueryScopes:
    def test_scope_included_in_combined_sql(self) -> None:
        """Combined SQL includes scope filter."""
        registry = PolicyRegistry()
        registry.register(
            QueryScopedPost,
            "read",
            lambda actor: QueryScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="Published posts",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(QueryScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        stmt = select(QueryScopedPost)
        result = explain_query(stmt, actor=actor, action="read", registry=registry)

        entity = result.entities[0]
        assert "org_id" in entity.combined_filter_sql
        assert "is_published" in entity.combined_filter_sql
        assert entity.scopes_applied == 1
        assert entity.scope_names == ["tenant"]

    def test_authorized_sql_matches_authorize_query(self) -> None:
        """explain_query authorized_sql matches authorize_query output."""
        registry = PolicyRegistry()
        registry.register(
            QueryScopedPost,
            "read",
            lambda actor: QueryScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(QueryScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        stmt = select(QueryScopedPost)

        explain_result = explain_query(stmt, actor=actor, action="read", registry=registry)
        authorized_stmt = authorize_query(stmt, actor=actor, action="read", registry=registry)
        authorized_sql = str(authorized_stmt.compile(compile_kwargs={"literal_binds": True}))

        assert explain_result.authorized_sql == authorized_sql

    def test_no_scopes_defaults_to_zero(self) -> None:
        """When no scopes registered, scopes_applied is 0."""
        registry = PolicyRegistry()
        registry.register(
            QueryScopedPost,
            "read",
            lambda actor: QueryScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="",
        )

        actor = MockActor(id=1)
        stmt = select(QueryScopedPost)
        result = explain_query(stmt, actor=actor, action="read", registry=registry)

        entity = result.entities[0]
        assert entity.scopes_applied == 0
        assert entity.scope_names == []

    def test_multiple_scopes_all_anded(self) -> None:
        """Multiple scopes are AND'd into the combined filter."""
        registry = PolicyRegistry()
        registry.register(
            QueryScopedPost,
            "read",
            lambda actor: true(),
            name="allow_all",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(QueryScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))
        registry.register_scope(ScopeRegistration(
            applies_to=(QueryScopedPost,),
            fn=lambda actor, Model: Model.is_published == True,  # noqa: E712
            name="published_filter",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        stmt = select(QueryScopedPost)
        result = explain_query(stmt, actor=actor, action="read", registry=registry)

        entity = result.entities[0]
        assert entity.scopes_applied == 2
        assert set(entity.scope_names) == {"tenant", "published_filter"}
        assert "org_id" in entity.combined_filter_sql
        assert "is_published" in entity.combined_filter_sql

    def test_to_dict_includes_scope_fields(self) -> None:
        """to_dict() includes scopes_applied and scope_names."""
        registry = PolicyRegistry()
        registry.register(
            QueryScopedPost,
            "read",
            lambda actor: QueryScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(QueryScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        stmt = select(QueryScopedPost)
        result = explain_query(stmt, actor=actor, action="read", registry=registry)

        d = result.to_dict()
        entity_dict = d["entities"][0]
        assert entity_dict["scopes_applied"] == 1
        assert entity_dict["scope_names"] == ["tenant"]

    def test_str_includes_scopes(self) -> None:
        """__str__() includes scope information."""
        registry = PolicyRegistry()
        registry.register(
            QueryScopedPost,
            "read",
            lambda actor: QueryScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(QueryScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        stmt = select(QueryScopedPost)
        result = explain_query(stmt, actor=actor, action="read", registry=registry)

        text = str(result)
        assert "Scopes (1): tenant" in text

    def test_deny_by_default_no_scopes(self) -> None:
        """When no policies exist (deny by default), scopes are not reported."""
        registry = PolicyRegistry()
        registry.register_scope(ScopeRegistration(
            applies_to=(QueryScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        stmt = select(QueryScopedPost)
        result = explain_query(stmt, actor=actor, action="read", registry=registry)

        entity = result.entities[0]
        assert entity.deny_by_default is True
        assert entity.scopes_applied == 0
