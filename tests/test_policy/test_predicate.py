"""Tests for policy/_predicate.py — composable predicates."""

from __future__ import annotations

from sqlalchemy import ColumnElement, true
from sqlalchemy.dialects import sqlite

from sqla_authz.policy import policy
from sqla_authz.policy._predicate import Predicate, always_allow, always_deny, predicate
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import MockActor, Post


def _compile_sql(expr: ColumnElement[bool]) -> str:
    """Compile a SQLAlchemy expression to a SQL string for assertions."""
    return str(expr.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))


class TestPredicate:
    """Predicate wraps a callable and supports composition."""

    def test_single_predicate_evaluation(self):
        p = Predicate(
            lambda actor: Post.is_published.is_(True),
            name="is_published",  # noqa: FBT003
        )
        actor = MockActor(id=1)
        result = p(actor)
        assert isinstance(result, ColumnElement)
        sql = _compile_sql(result)
        assert "is_published" in sql

    def test_and_composition(self):
        pred_a = Predicate(
            lambda actor: Post.is_published.is_(True),
            name="published",  # noqa: FBT003
        )
        pred_b = Predicate(lambda actor: Post.author_id == actor.id, name="author")
        combined = pred_a & pred_b
        actor = MockActor(id=42)
        sql = _compile_sql(combined(actor))
        assert "is_published" in sql
        assert "author_id" in sql
        assert "AND" in sql

    def test_or_composition(self):
        pred_a = Predicate(
            lambda actor: Post.is_published.is_(True),
            name="published",  # noqa: FBT003
        )
        pred_b = Predicate(lambda actor: Post.author_id == actor.id, name="author")
        combined = pred_a | pred_b
        actor = MockActor(id=42)
        sql = _compile_sql(combined(actor))
        assert "is_published" in sql
        assert "author_id" in sql
        assert "OR" in sql

    def test_not_composition(self):
        pred_a = Predicate(
            lambda actor: Post.is_published.is_(True),
            name="published",  # noqa: FBT003
        )
        negated = ~pred_a
        actor = MockActor(id=1)
        sql = _compile_sql(negated(actor))
        assert "is_published" in sql
        # SQLAlchemy may render NOT(x IS 1) in different ways
        assert "NOT" in sql.upper() or "!=" in sql

    def test_nested_composition(self):
        pred_a = Predicate(
            lambda actor: Post.is_published.is_(True),
            name="published",  # noqa: FBT003
        )
        pred_b = Predicate(lambda actor: Post.author_id == actor.id, name="author")
        pred_c = Predicate(lambda actor: Post.title == "special", name="special")
        combined = pred_a | (pred_b & pred_c)
        actor = MockActor(id=42)
        sql = _compile_sql(combined(actor))
        assert "is_published" in sql
        assert "author_id" in sql
        assert "title" in sql
        assert "OR" in sql
        assert "AND" in sql

    def test_always_allow(self):
        actor = MockActor(id=1)
        result = always_allow(actor)
        sql = _compile_sql(result)
        assert "true" in sql.lower() or "1" in sql

    def test_always_deny(self):
        actor = MockActor(id=1)
        result = always_deny(actor)
        sql = _compile_sql(result)
        assert "false" in sql.lower() or "0" in sql

    def test_predicate_decorator_factory(self):
        @predicate
        def is_published(actor: MockActor) -> ColumnElement[bool]:
            return Post.is_published.is_(True)  # noqa: FBT003

        assert isinstance(is_published, Predicate)
        assert is_published.name == "is_published"
        result = is_published(MockActor(id=1))
        assert isinstance(result, ColumnElement)

    def test_predicate_name_from_init(self):
        p = Predicate(lambda a: true(), name="my_pred")
        assert p.name == "my_pred"

    def test_predicate_repr(self):
        p = Predicate(lambda a: true(), name="my_pred")
        assert repr(p) == "Predicate('my_pred')"

    def test_composed_predicate_name(self):
        a = Predicate(lambda actor: true(), name="a")
        b = Predicate(lambda actor: true(), name="b")
        assert (a & b).name == "(a & b)"
        assert (a | b).name == "(a | b)"
        assert (~a).name == "~a"


class TestPredicateWithPolicy:
    """Predicates integrate with the @policy decorator."""

    def test_predicate_kwarg_on_policy(self):
        registry = PolicyRegistry()
        is_published = Predicate(
            lambda actor: Post.is_published.is_(True),  # noqa: FBT003
            name="is_published",
        )

        @policy(Post, "read", predicate=is_published, registry=registry)
        def post_read_policy(actor: MockActor) -> ColumnElement[bool]:
            """Published posts are readable."""
            return true()  # body ignored when predicate= is set

        policies = registry.lookup(Post, "read")
        assert len(policies) == 1
        assert policies[0].name == "post_read_policy"
        assert policies[0].description == "Published posts are readable."
        # The registered fn should use the predicate, not the function body
        actor = MockActor(id=1)
        sql = _compile_sql(policies[0].fn(actor))
        assert "is_published" in sql

    def test_composed_predicate_with_policy(self):
        registry = PolicyRegistry()
        is_published = Predicate(
            lambda actor: Post.is_published.is_(True),  # noqa: FBT003
            name="published",
        )
        is_author = Predicate(lambda actor: Post.author_id == actor.id, name="author")

        @policy(Post, "read", predicate=is_published | is_author, registry=registry)
        def post_read_policy(actor: MockActor) -> ColumnElement[bool]:
            """Read published or own posts."""
            return true()

        policies = registry.lookup(Post, "read")
        assert len(policies) == 1
        actor = MockActor(id=99)
        sql = _compile_sql(policies[0].fn(actor))
        assert "is_published" in sql
        assert "author_id" in sql
        assert "OR" in sql

    def test_policy_without_predicate_still_works(self):
        """Backward compat: @policy without predicate= uses the function body."""
        registry = PolicyRegistry()

        @policy(Post, "read", registry=registry)
        def post_read(actor: MockActor) -> ColumnElement[bool]:
            return Post.is_published.is_(True)  # noqa: FBT003

        policies = registry.lookup(Post, "read")
        assert len(policies) == 1
        actor = MockActor(id=1)
        sql = _compile_sql(policies[0].fn(actor))
        assert "is_published" in sql
