"""Edge case tests for sqla-authz — boundary conditions and unusual inputs."""

from __future__ import annotations

from sqlalchemy import ColumnElement, false, literal_column, select, true

from sqla_authz.compiler._expression import evaluate_policies
from sqla_authz.compiler._query import authorize_query
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import MockActor, Post, User


class TestAuthorizeQueryEmptySelect:
    """authorize_query with a select() that has no ORM entities."""

    def test_empty_select_literal_column(self):
        """select(literal_column('1')) has no entity — should pass through unchanged."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="p",
            description="",
        )
        stmt = select(literal_column("1"))
        actor = MockActor(id=1)
        result = authorize_query(stmt, actor=actor, action="read", registry=registry)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        # No entity was found, so no WHERE clause should be added
        assert "is_published" not in sql

    def test_empty_select_no_registry_entries(self):
        """select(literal_column('1')) with empty registry — no crash."""
        registry = PolicyRegistry()
        stmt = select(literal_column("1"))
        actor = MockActor(id=1)
        result = authorize_query(stmt, actor=actor, action="read", registry=registry)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        # Should not contain any WHERE FALSE since there are no entities to filter
        assert "WHERE" not in sql.upper() or "1 != 1" not in sql


class TestLargeActorIds:
    """Test with very large actor.id values (max int64)."""

    def test_max_int64_actor_id(self):
        """Policy with actor.id = 2**63 - 1 should produce valid SQL."""
        max_int64 = 2**63 - 1
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="",
        )
        actor = MockActor(id=max_int64)
        result = evaluate_policies(registry, Post, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert str(max_int64) in sql

    def test_max_int64_authorize_query(self):
        """authorize_query with max int64 actor.id produces correct SQL."""
        max_int64 = 2**63 - 1
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="",
        )
        stmt = select(Post)
        actor = MockActor(id=max_int64)
        result = authorize_query(stmt, actor=actor, action="read", registry=registry)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert str(max_int64) in sql
        assert "WHERE" in sql

    def test_max_int64_returns_correct_rows(self, session, sample_data):
        """Database query with max int64 actor.id returns no rows (no matching author)."""
        max_int64 = 2**63 - 1
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="",
        )
        actor = MockActor(id=max_int64)
        stmt = authorize_query(select(Post), actor=actor, action="read", registry=registry)
        results = session.execute(stmt).scalars().all()
        assert len(results) == 0

    def test_zero_actor_id(self):
        """Policy with actor.id = 0 should produce valid SQL."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="",
        )
        actor = MockActor(id=0)
        result = evaluate_policies(registry, Post, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "author_id" in sql

    def test_negative_actor_id(self):
        """Policy with negative actor.id should produce valid SQL."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="",
        )
        actor = MockActor(id=-1)
        result = evaluate_policies(registry, Post, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "-1" in sql


class TestUnicodeActorIds:
    """Test with unicode string actor IDs."""

    def test_unicode_string_actor_id(self):
        """Policy with a unicode string actor.id should produce valid SQL."""
        registry = PolicyRegistry()
        registry.register(
            User,
            "read",
            lambda actor: User.name == actor.id,
            name="name_match",
            description="",
        )
        actor = MockActor(id="utilisateur-\u00e9l\u00e8ve")
        result = evaluate_policies(registry, User, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "utilisateur" in sql

    def test_emoji_actor_id(self):
        """Policy with emoji actor.id should produce valid SQL."""
        registry = PolicyRegistry()
        registry.register(
            User,
            "read",
            lambda actor: User.name == actor.id,
            name="name_match",
            description="",
        )
        actor = MockActor(id="\U0001f600\U0001f680")
        result = evaluate_policies(registry, User, "read", actor)
        assert isinstance(result, ColumnElement)

    def test_cjk_actor_id(self):
        """Policy with CJK characters in actor.id should produce valid SQL."""
        registry = PolicyRegistry()
        registry.register(
            User,
            "read",
            lambda actor: User.name == actor.id,
            name="name_match",
            description="",
        )
        actor = MockActor(id="\u7528\u6237\u540d")
        result = evaluate_policies(registry, User, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "\u7528\u6237\u540d" in sql

    def test_empty_string_actor_id(self):
        """Policy with empty string actor.id should produce valid SQL."""
        registry = PolicyRegistry()
        registry.register(
            User,
            "read",
            lambda actor: User.name == actor.id,
            name="name_match",
            description="",
        )
        actor = MockActor(id="")
        result = evaluate_policies(registry, User, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "users.name" in sql


class TestMultiplePoliciesOrComposition:
    """Verify that multiple policies for the same (model, action) are OR'd."""

    def test_two_policies_ored_sql(self):
        """Two policies produce an OR expression in the compiled SQL."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="published",
            description="",
        )
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own",
            description="",
        )
        actor = MockActor(id=1)
        result = evaluate_policies(registry, Post, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "is_published" in sql
        assert "author_id" in sql
        assert "OR" in sql.upper()

    def test_three_policies_ored(self):
        """Three policies for the same key are all OR'd together."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="published",
            description="",
        )
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own",
            description="",
        )
        registry.register(
            Post,
            "read",
            lambda actor: Post.title == "Special",
            name="special_title",
            description="",
        )
        actor = MockActor(id=1)
        result = evaluate_policies(registry, Post, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "is_published" in sql
        assert "author_id" in sql
        assert "title" in sql
        # With 3 conditions OR'd, should have at least 2 OR operators
        assert sql.upper().count("OR") >= 2

    def test_multiple_policies_database_correctness(self, session, sample_data):
        """OR composition returns the union of rows matched by each policy."""
        registry = PolicyRegistry()
        # Policy 1: published posts
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="published",
            description="",
        )
        # Policy 2: own posts (by author_id)
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own",
            description="",
        )

        # Alice (id=1) owns post1 (published) and post2 (draft).
        # Published posts are post1 and post3.
        # Union: post1, post2, post3 = 3 rows.
        actor = MockActor(id=1)
        stmt = authorize_query(select(Post), actor=actor, action="read", registry=registry)
        results = session.execute(stmt).scalars().all()
        assert len(results) == 3

        # Charlie (id=3) owns no posts.
        # Published posts are post1 and post3.
        # Union: post1, post3 = 2 rows.
        actor_charlie = MockActor(id=3)
        stmt2 = authorize_query(
            select(Post), actor=actor_charlie, action="read", registry=registry
        )
        results2 = session.execute(stmt2).scalars().all()
        assert len(results2) == 2

    def test_single_policy_no_or(self):
        """A single policy should not produce an OR expression."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="published",
            description="",
        )
        actor = MockActor(id=1)
        result = evaluate_policies(registry, Post, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "is_published" in sql
        assert "OR" not in sql.upper()


class TestPolicyLiteralTrueFalse:
    """Test policies returning sqlalchemy.true() and sqlalchemy.false()."""

    def test_policy_returning_true_allows_all_rows(self, session, sample_data):
        """A policy returning true() should allow all rows through."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: true(),
            name="allow_all",
            description="",
        )
        actor = MockActor(id=99)
        stmt = authorize_query(select(Post), actor=actor, action="read", registry=registry)
        results = session.execute(stmt).scalars().all()
        # All 3 posts should be returned
        assert len(results) == 3

    def test_policy_returning_false_denies_all_rows(self, session, sample_data):
        """A policy returning false() should deny all rows."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: false(),
            name="deny_all",
            description="",
        )
        actor = MockActor(id=1)
        stmt = authorize_query(select(Post), actor=actor, action="read", registry=registry)
        results = session.execute(stmt).scalars().all()
        assert len(results) == 0

    def test_true_sql_expression(self):
        """true() policy should compile to a truthy SQL expression."""
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

    def test_false_sql_expression(self):
        """false() policy should compile to a falsy SQL expression."""
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

    def test_true_ored_with_condition(self):
        """true() OR'd with another condition should still allow everything."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: true(),
            name="allow_all",
            description="",
        )
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="published",
            description="",
        )
        actor = MockActor(id=1)
        result = evaluate_policies(registry, Post, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        # true OR anything = true
        assert "true" in sql.lower() or "1 = 1" in sql

    def test_true_ored_with_condition_returns_all_rows(self, session, sample_data):
        """true() OR'd with a condition should return all rows."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: true(),
            name="allow_all",
            description="",
        )
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="published",
            description="",
        )
        actor = MockActor(id=99)
        stmt = authorize_query(select(Post), actor=actor, action="read", registry=registry)
        results = session.execute(stmt).scalars().all()
        assert len(results) == 3

    def test_false_ored_with_condition(self, session, sample_data):
        """false() OR'd with a real condition — only the real condition applies."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: false(),
            name="deny_all",
            description="",
        )
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="published",
            description="",
        )
        actor = MockActor(id=99)
        stmt = authorize_query(select(Post), actor=actor, action="read", registry=registry)
        results = session.execute(stmt).scalars().all()
        # false OR is_published = is_published — only published posts
        assert len(results) == 2
        assert all(p.is_published for p in results)

    def test_no_policy_returns_false_by_default(self):
        """No policies at all should return WHERE FALSE (deny by default)."""
        registry = PolicyRegistry()
        actor = MockActor(id=1)
        result = evaluate_policies(registry, Post, "read", actor)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "false" in sql.lower() or "1 != 1" in sql
