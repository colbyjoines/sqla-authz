"""Tests for the Python-side expression evaluator (eval_expression)."""

from __future__ import annotations

import pytest
from sqlalchemy import false, true
from sqlalchemy.orm import Session

from sqla_authz.compiler._eval import eval_expression
from sqla_authz.config._config import _reset_global_config, configure
from sqla_authz.exceptions import UnloadedRelationshipError, UnsupportedExpressionError
from tests.conftest import MockActor, Organization, Post, User

# ---------------------------------------------------------------------------
# Simple equality
# ---------------------------------------------------------------------------


class TestSimpleEquality:
    """Tests for basic column == value comparisons."""

    def test_simple_equality_true(self, session: Session, sample_data):
        """Published post matches is_published == True."""
        post = sample_data["posts"][0]  # is_published=True
        expr = Post.is_published == True  # noqa: E712
        assert eval_expression(expr, post) is True

    def test_simple_equality_false(self, session: Session, sample_data):
        """Draft post does NOT match is_published == True."""
        post = sample_data["posts"][1]  # is_published=False
        expr = Post.is_published == True  # noqa: E712
        assert eval_expression(expr, post) is False


# ---------------------------------------------------------------------------
# Actor binding (BindParameter)
# ---------------------------------------------------------------------------


class TestActorBinding:
    """Tests for expressions containing actor-bound parameters."""

    def test_actor_binding_match(self, session: Session, sample_data):
        """Post.author_id == actor.id where actor.id matches author_id."""
        post = sample_data["posts"][0]  # author_id=1
        actor = MockActor(id=1)
        expr = Post.author_id == actor.id
        assert eval_expression(expr, post) is True

    def test_actor_binding_no_match(self, session: Session, sample_data):
        """Post.author_id == actor.id where actor.id differs."""
        post = sample_data["posts"][0]  # author_id=1
        actor = MockActor(id=999)
        expr = Post.author_id == actor.id
        assert eval_expression(expr, post) is False


# ---------------------------------------------------------------------------
# Boolean combinators (OR, AND, NOT)
# ---------------------------------------------------------------------------


class TestBooleanCombinators:
    """Tests for OR, AND, NOT expression combinators."""

    def test_or_expression_first_true(self, session: Session, sample_data):
        """OR: published post matches even if not authored by actor."""
        post = sample_data["posts"][0]  # published, author_id=1
        actor = MockActor(id=99)
        expr = (Post.is_published == True) | (Post.author_id == actor.id)  # noqa: E712
        assert eval_expression(expr, post) is True

    def test_or_expression_second_true(self, session: Session, sample_data):
        """OR: draft by author matches on author_id."""
        post = sample_data["posts"][1]  # draft, author_id=1
        actor = MockActor(id=1)
        expr = (Post.is_published == True) | (Post.author_id == actor.id)  # noqa: E712
        assert eval_expression(expr, post) is True

    def test_or_expression_both_false(self, session: Session, sample_data):
        """OR: draft by other author -> False."""
        post = sample_data["posts"][1]  # draft, author_id=1
        actor = MockActor(id=99)
        expr = (Post.is_published == True) | (Post.author_id == actor.id)  # noqa: E712
        assert eval_expression(expr, post) is False

    def test_and_expression_both_true(self, session: Session, sample_data):
        """AND: published + authored by actor -> True."""
        post = sample_data["posts"][0]  # published, author_id=1
        actor = MockActor(id=1)
        expr = (Post.is_published == True) & (Post.author_id == actor.id)  # noqa: E712
        assert eval_expression(expr, post) is True

    def test_and_expression_one_false(self, session: Session, sample_data):
        """AND: published but NOT authored by actor -> False."""
        post = sample_data["posts"][0]  # published, author_id=1
        actor = MockActor(id=99)
        expr = (Post.is_published == True) & (Post.author_id == actor.id)  # noqa: E712
        assert eval_expression(expr, post) is False

    def test_not_expression_negates_true(self, session: Session, sample_data):
        """NOT: ~(is_published == True) on published post -> False."""
        post = sample_data["posts"][0]  # published
        expr = ~(Post.is_published == True)  # noqa: E712
        assert eval_expression(expr, post) is False

    def test_not_expression_negates_false(self, session: Session, sample_data):
        """NOT: ~(is_published == True) on draft -> True."""
        post = sample_data["posts"][1]  # draft
        expr = ~(Post.is_published == True)  # noqa: E712
        assert eval_expression(expr, post) is True


# ---------------------------------------------------------------------------
# Literals
# ---------------------------------------------------------------------------


class TestLiterals:
    """Tests for true()/false() literal expressions."""

    def test_true_literal(self, session: Session, sample_data):
        """true() always evaluates to True."""
        post = sample_data["posts"][0]
        assert eval_expression(true(), post) is True

    def test_false_literal(self, session: Session, sample_data):
        """false() always evaluates to False."""
        post = sample_data["posts"][0]
        assert eval_expression(false(), post) is False


# ---------------------------------------------------------------------------
# Comparison operators
# ---------------------------------------------------------------------------


class TestComparisonOperators:
    """Tests for <, >, <=, >= operators."""

    def test_greater_than_true(self, session: Session, sample_data):
        """Post.author_id > 0 where author_id=1 -> True."""
        post = sample_data["posts"][0]  # author_id=1
        expr = Post.author_id > 0
        assert eval_expression(expr, post) is True

    def test_greater_than_false(self, session: Session, sample_data):
        """Post.author_id > 100 where author_id=1 -> False."""
        post = sample_data["posts"][0]  # author_id=1
        expr = Post.author_id > 100
        assert eval_expression(expr, post) is False

    def test_less_than(self, session: Session, sample_data):
        """Post.author_id < 10 where author_id=1 -> True."""
        post = sample_data["posts"][0]
        expr = Post.author_id < 10
        assert eval_expression(expr, post) is True

    def test_greater_equal(self, session: Session, sample_data):
        """Post.author_id >= 1 where author_id=1 -> True (boundary)."""
        post = sample_data["posts"][0]
        expr = Post.author_id >= 1
        assert eval_expression(expr, post) is True

    def test_less_equal(self, session: Session, sample_data):
        """Post.author_id <= 1 where author_id=1 -> True (boundary)."""
        post = sample_data["posts"][0]
        expr = Post.author_id <= 1
        assert eval_expression(expr, post) is True

    def test_not_equal_true(self, session: Session, sample_data):
        """Post.author_id != 99 where author_id=1 -> True."""
        post = sample_data["posts"][0]
        expr = Post.author_id != 99
        assert eval_expression(expr, post) is True

    def test_not_equal_false(self, session: Session, sample_data):
        """Post.author_id != 1 where author_id=1 -> False."""
        post = sample_data["posts"][0]
        expr = Post.author_id != 1
        assert eval_expression(expr, post) is False


# ---------------------------------------------------------------------------
# IN operator
# ---------------------------------------------------------------------------


class TestInOperator:
    """Tests for the IN clause."""

    def test_in_operator_match(self, session: Session, sample_data):
        """Post.author_id.in_([1, 2, 3]) where author_id=1 -> True."""
        post = sample_data["posts"][0]  # author_id=1
        expr = Post.author_id.in_([1, 2, 3])
        assert eval_expression(expr, post) is True

    def test_in_operator_no_match(self, session: Session, sample_data):
        """Post.author_id.in_([10, 20, 30]) where author_id=1 -> False."""
        post = sample_data["posts"][0]
        expr = Post.author_id.in_([10, 20, 30])
        assert eval_expression(expr, post) is False

    def test_in_operator_empty_list(self, session: Session, sample_data):
        """Post.author_id.in_([]) -> False (empty IN clause)."""
        post = sample_data["posts"][0]
        expr = Post.author_id.in_([])
        assert eval_expression(expr, post) is False


# ---------------------------------------------------------------------------
# NULL checks
# ---------------------------------------------------------------------------


class TestNullChecks:
    """Tests for IS NULL / IS NOT NULL."""

    def test_is_null_true(self, session: Session, sample_data):
        """User.org_id IS NULL where org_id is None -> True."""
        charlie = sample_data["users"][2]  # org_id=None
        expr = User.org_id.is_(None)
        assert eval_expression(expr, charlie) is True

    def test_is_null_false(self, session: Session, sample_data):
        """User.org_id IS NULL where org_id=1 -> False."""
        alice = sample_data["users"][0]  # org_id=1
        expr = User.org_id.is_(None)
        assert eval_expression(expr, alice) is False

    def test_is_not_null_true(self, session: Session, sample_data):
        """User.org_id IS NOT NULL where org_id=1 -> True."""
        alice = sample_data["users"][0]
        expr = User.org_id.is_not(None)
        assert eval_expression(expr, alice) is True

    def test_is_not_null_false(self, session: Session, sample_data):
        """User.org_id IS NOT NULL where org_id=None -> False."""
        charlie = sample_data["users"][2]
        expr = User.org_id.is_not(None)
        assert eval_expression(expr, charlie) is False


# ---------------------------------------------------------------------------
# Relationship: has() — many-to-one / one-to-one
# ---------------------------------------------------------------------------


class TestHasRelationship:
    """Tests for .has() (EXISTS subquery) evaluation on loaded relationships."""

    def test_has_relationship_loaded_match(self, session: Session, sample_data):
        """Post.author.has(User.org_id == 1) with author in org 1 -> True."""
        post = sample_data["posts"][0]  # author_id=1 (Alice, org_id=1)
        # Ensure relationship is loaded
        _ = post.author
        expr = Post.author.has(User.org_id == 1)
        assert eval_expression(expr, post) is True

    def test_has_relationship_loaded_no_match(self, session: Session, sample_data):
        """Post.author.has(User.org_id == 99) with author in org 1 -> False."""
        post = sample_data["posts"][0]
        _ = post.author
        expr = Post.author.has(User.org_id == 99)
        assert eval_expression(expr, post) is False

    def test_has_relationship_none(self, session: Session, sample_data):
        """has() on a nullable relationship that is None -> False."""
        # Charlie has no org
        charlie = sample_data["users"][2]  # org_id=None
        _ = charlie.organization  # load it (will be None)
        expr = User.organization.has(Organization.name == "Acme Corp")
        assert eval_expression(expr, charlie) is False


# ---------------------------------------------------------------------------
# Relationship: any() — one-to-many / many-to-many
# ---------------------------------------------------------------------------


class TestAnyRelationship:
    """Tests for .any() (EXISTS subquery) evaluation on loaded relationships."""

    def test_any_relationship_loaded_match(self, session: Session, sample_data):
        """User.posts.any(Post.is_published == True) with published posts -> True."""
        alice = sample_data["users"][0]  # has published post
        _ = alice.posts  # ensure loaded
        expr = User.posts.any(Post.is_published == True)  # noqa: E712
        assert eval_expression(expr, alice) is True

    def test_any_relationship_empty(self, session: Session, sample_data):
        """User.posts.any(...) with no posts -> False."""
        charlie = sample_data["users"][2]  # no posts
        _ = charlie.posts  # ensure loaded (empty list)
        expr = User.posts.any(Post.is_published == True)  # noqa: E712
        assert eval_expression(expr, charlie) is False

    def test_any_relationship_no_match(self, session: Session, sample_data):
        """any() with loaded items but none matching -> False."""
        bob = sample_data["users"][1]  # has 1 published post (post3)
        _ = bob.posts
        # Bob's post (id=3) is published, so check for draft
        expr = User.posts.any(Post.is_published == False)  # noqa: E712
        assert eval_expression(expr, bob) is False


# ---------------------------------------------------------------------------
# Unloaded relationships
# ---------------------------------------------------------------------------


class TestUnloadedRelationship:
    """Tests for unloaded relationship handling based on config."""

    def test_unloaded_relationship_deny_mode(self, engine, session: Session, sample_data):
        """Default 'deny' mode returns False for unloaded relationships."""
        _reset_global_config()
        try:
            # Get a fresh post without loading author
            post = session.get(Post, 1)
            # Expire the author relationship so it's unloaded
            session.expire(post, ["author"])
            # Evict from session so lazy load won't work
            session.expunge(post)

            expr = Post.author.has(User.org_id == 1)
            assert eval_expression(expr, post) is False
        finally:
            _reset_global_config()

    def test_unloaded_relationship_raise_mode(self, engine, session: Session, sample_data):
        """'raise' mode raises UnloadedRelationshipError."""
        _reset_global_config()
        configure(on_unloaded_relationship="raise")
        try:
            post = session.get(Post, 1)
            session.expire(post, ["author"])
            session.expunge(post)

            expr = Post.author.has(User.org_id == 1)
            with pytest.raises(UnloadedRelationshipError) as exc_info:
                eval_expression(expr, post)

            assert "author" in str(exc_info.value)
        finally:
            _reset_global_config()


# ---------------------------------------------------------------------------
# Unsupported expression
# ---------------------------------------------------------------------------


class TestUnsupportedExpression:
    """Tests for unsupported expression types."""

    def test_unsupported_expression_raises(self, session: Session, sample_data):
        """Passing an unsupported expression type raises UnsupportedExpressionError."""
        from sqlalchemy import func

        post = sample_data["posts"][0]
        # func.lower() returns a Function element, not a supported comparison
        expr = func.lower(Post.title)
        with pytest.raises(UnsupportedExpressionError):
            eval_expression(expr, post)
