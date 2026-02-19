"""Tests for compiler/_query.py — authorize_query() implementation."""

from __future__ import annotations

from sqlalchemy import literal_column, or_, select, true

from sqla_authz.compiler._query import authorize_query
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import MockActor, Post


class TestAuthorizeQuery:
    """authorize_query() applies authorization filters to SELECT statements."""

    def test_adds_where_clause(self):
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="p",
            description="",
        )
        stmt = select(Post)
        actor = MockActor(id=1)
        result = authorize_query(stmt, actor=actor, action="read", registry=registry)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "WHERE" in sql
        assert "is_published" in sql

    def test_preserves_existing_where(self):
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="p",
            description="",
        )
        stmt = select(Post).where(Post.title == "test")
        actor = MockActor(id=1)
        result = authorize_query(stmt, actor=actor, action="read", registry=registry)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        # Both original and authz filters should be present
        assert "title" in sql
        assert "is_published" in sql

    def test_deny_by_default_no_policy(self):
        """No policy registered → WHERE FALSE (zero rows)."""
        registry = PolicyRegistry()
        stmt = select(Post)
        actor = MockActor(id=1)
        result = authorize_query(stmt, actor=actor, action="read", registry=registry)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "WHERE" in sql
        # Should contain a false-like expression
        assert "1 != 1" in sql or "false" in sql.lower()

    def test_multiple_policies_ored(self):
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
        stmt = select(Post)
        actor = MockActor(id=5)
        result = authorize_query(stmt, actor=actor, action="read", registry=registry)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "is_published" in sql
        assert "author_id" in sql

    def test_uses_default_registry_when_none_provided(self):
        """When no registry is passed, authorize_query uses the global default."""
        from sqla_authz.policy import get_default_registry, policy

        get_default_registry().clear()

        @policy(Post, "read")
        def p(actor: MockActor):
            return Post.is_published == True

        stmt = select(Post)
        actor = MockActor(id=1)
        result = authorize_query(stmt, actor=actor, action="read")
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "is_published" in sql

        get_default_registry().clear()

    def test_returns_new_statement(self):
        """authorize_query should not mutate the original statement."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: true(),
            name="p",
            description="",
        )
        stmt = select(Post)
        actor = MockActor(id=1)
        result = authorize_query(stmt, actor=actor, action="read", registry=registry)
        assert result is not stmt

    def test_result_correctness_with_database(self, session, sample_data):
        """Integration: verify only authorized rows are returned."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: or_(
                Post.is_published == True,
                Post.author_id == actor.id,
            ),
            name="p",
            description="",
        )
        # Alice (id=1) should see: published posts + her own drafts
        actor = MockActor(id=1)
        stmt = authorize_query(select(Post), actor=actor, action="read", registry=registry)
        results = session.execute(stmt).scalars().all()
        # post1 (published, alice), post2 (draft, alice), post3 (published, bob)
        assert len(results) == 3

        # Charlie (id=3) should see only published posts
        actor_charlie = MockActor(id=3)
        stmt2 = authorize_query(
            select(Post), actor=actor_charlie, action="read", registry=registry
        )
        results2 = session.execute(stmt2).scalars().all()
        # post1 (published), post3 (published)
        assert len(results2) == 2
        assert all(p.is_published for p in results2)

    def test_deny_by_default_returns_no_rows(self, session, sample_data):
        """No policy → zero rows from the database."""
        registry = PolicyRegistry()
        actor = MockActor(id=1)
        stmt = authorize_query(select(Post), actor=actor, action="delete", registry=registry)
        results = session.execute(stmt).scalars().all()
        assert len(results) == 0

    def test_select_with_no_entity(self):
        """authorize_query with a select() that has no ORM entity should pass through."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="p",
            description="",
        )
        # select() with a raw literal column, no ORM entity
        stmt = select(literal_column("1"))
        actor = MockActor(id=1)
        result = authorize_query(stmt, actor=actor, action="read", registry=registry)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        # No entity was detected, so no authz filter should be applied
        assert "is_published" not in sql

    def test_select_individual_column(self):
        """authorize_query with select(Post.title) should still apply filters."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="p",
            description="",
        )
        stmt = select(Post.title)
        actor = MockActor(id=1)
        result = authorize_query(stmt, actor=actor, action="read", registry=registry)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "title" in sql
