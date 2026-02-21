"""Tests for safe_get() and safe_get_or_raise() — authorized PK lookups."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, true
from sqlalchemy.orm import Session, sessionmaker

from sqla_authz.exceptions import AuthorizationDenied
from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.session._safe_get import safe_get, safe_get_or_raise
from tests.conftest import Base, MockActor, Organization, Post, User

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def safe_get_engine():
    """Fresh engine for safe_get tests."""
    eng = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def registry() -> PolicyRegistry:
    """Fresh registry per test."""
    return PolicyRegistry()


def _seed_data(sess: Session) -> None:
    """Seed test data into a session."""
    org = Organization(id=1, name="Acme Corp")
    sess.add(org)

    alice = User(id=1, name="Alice", role="admin", org_id=1)
    bob = User(id=2, name="Bob", role="editor", org_id=1)
    sess.add_all([alice, bob])

    post1 = Post(id=1, title="Public Post", is_published=True, author_id=1)
    post2 = Post(id=2, title="Draft Post", is_published=False, author_id=1)
    post3 = Post(id=3, title="Bob's Post", is_published=True, author_id=2)
    sess.add_all([post1, post2, post3])
    sess.flush()


# ---------------------------------------------------------------------------
# Tests: safe_get
# ---------------------------------------------------------------------------


class TestSafeGet:
    """Test safe_get() — returns None if denied or not found."""

    def test_returns_authorized_entity(self, safe_get_engine, registry) -> None:
        """safe_get returns entity when actor is authorized."""
        actor = MockActor(id=1, role="admin")

        # Policy: allow published posts
        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published_only",
            description="",
        )

        factory = sessionmaker(bind=safe_get_engine)
        with factory() as sess:
            _seed_data(sess)
            result = safe_get(sess, Post, 1, actor=actor, registry=registry)
            assert result is not None
            assert result.id == 1
            assert result.is_published is True

    def test_returns_none_when_denied(self, safe_get_engine, registry) -> None:
        """safe_get returns None when actor is not authorized."""
        actor = MockActor(id=1, role="viewer")

        # Policy: only published posts
        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published_only",
            description="",
        )

        factory = sessionmaker(bind=safe_get_engine)
        with factory() as sess:
            _seed_data(sess)
            # Post 2 is a draft (not published) — should be denied
            result = safe_get(sess, Post, 2, actor=actor, registry=registry)
            assert result is None

    def test_returns_none_when_not_found(self, safe_get_engine, registry) -> None:
        """safe_get returns None when entity does not exist."""
        actor = MockActor(id=1)

        registry.register(
            Post,
            "read",
            lambda a: true(),
            name="allow_all",
            description="",
        )

        factory = sessionmaker(bind=safe_get_engine)
        with factory() as sess:
            _seed_data(sess)
            result = safe_get(sess, Post, 999, actor=actor, registry=registry)
            assert result is None

    def test_uses_custom_action(self, safe_get_engine, registry) -> None:
        """safe_get supports custom action parameter."""
        actor = MockActor(id=1)

        # "read" allows all; "delete" denies all
        registry.register(
            Post,
            "read",
            lambda a: true(),
            name="read_all",
            description="",
        )
        registry.register(
            Post,
            "delete",
            lambda a: Post.author_id == a.id,
            name="own_delete",
            description="",
        )

        factory = sessionmaker(bind=safe_get_engine)
        with factory() as sess:
            _seed_data(sess)
            # Read: authorized
            result = safe_get(sess, Post, 3, actor=actor, action="read", registry=registry)
            assert result is not None

            # Delete: denied (Bob's post, actor is Alice)
            result = safe_get(sess, Post, 3, actor=actor, action="delete", registry=registry)
            assert result is None

    def test_actor_based_policy(self, safe_get_engine, registry) -> None:
        """safe_get correctly evaluates actor-dependent policies."""
        # Policy: only own posts
        registry.register(
            Post,
            "read",
            lambda a: Post.author_id == a.id,
            name="own_posts",
            description="",
        )

        factory = sessionmaker(bind=safe_get_engine)
        with factory() as sess:
            _seed_data(sess)

            # Alice (id=1) can see her own posts
            alice = MockActor(id=1)
            result = safe_get(sess, Post, 1, actor=alice, registry=registry)
            assert result is not None
            assert result.author_id == 1

            # Alice cannot see Bob's post
            result = safe_get(sess, Post, 3, actor=alice, registry=registry)
            assert result is None

            # Bob (id=2) can see his own post
            bob = MockActor(id=2)
            result = safe_get(sess, Post, 3, actor=bob, registry=registry)
            assert result is not None
            assert result.author_id == 2


# ---------------------------------------------------------------------------
# Tests: safe_get_or_raise
# ---------------------------------------------------------------------------


class TestSafeGetOrRaise:
    """Test safe_get_or_raise() — raises AuthorizationDenied if denied."""

    def test_returns_authorized_entity(self, safe_get_engine, registry) -> None:
        """safe_get_or_raise returns entity when authorized."""
        actor = MockActor(id=1)

        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published_only",
            description="",
        )

        factory = sessionmaker(bind=safe_get_engine)
        with factory() as sess:
            _seed_data(sess)
            result = safe_get_or_raise(sess, Post, 1, actor=actor, registry=registry)
            assert result is not None
            assert result.id == 1

    def test_raises_when_denied(self, safe_get_engine, registry) -> None:
        """safe_get_or_raise raises AuthorizationDenied when denied."""
        actor = MockActor(id=1, role="viewer")

        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published_only",
            description="",
        )

        factory = sessionmaker(bind=safe_get_engine)
        with factory() as sess:
            _seed_data(sess)
            with pytest.raises(AuthorizationDenied) as exc_info:
                safe_get_or_raise(sess, Post, 2, actor=actor, registry=registry)

            exc = exc_info.value
            assert exc.actor is actor
            assert exc.action == "read"
            assert exc.resource_type == "Post"

    def test_returns_none_when_not_found(self, safe_get_engine, registry) -> None:
        """safe_get_or_raise returns None when entity does not exist (no raise)."""
        actor = MockActor(id=1)

        registry.register(
            Post,
            "read",
            lambda a: true(),
            name="allow_all",
            description="",
        )

        factory = sessionmaker(bind=safe_get_engine)
        with factory() as sess:
            _seed_data(sess)
            result = safe_get_or_raise(sess, Post, 999, actor=actor, registry=registry)
            assert result is None

    def test_custom_error_message(self, safe_get_engine, registry) -> None:
        """safe_get_or_raise uses custom message when provided."""
        actor = MockActor(id=1)

        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published_only",
            description="",
        )

        factory = sessionmaker(bind=safe_get_engine)
        with factory() as sess:
            _seed_data(sess)
            with pytest.raises(AuthorizationDenied, match="Custom denial"):
                safe_get_or_raise(
                    sess,
                    Post,
                    2,
                    actor=actor,
                    registry=registry,
                    message="Custom denial",
                )

    def test_uses_custom_action(self, safe_get_engine, registry) -> None:
        """safe_get_or_raise supports custom action parameter."""
        actor = MockActor(id=1)

        registry.register(
            Post,
            "delete",
            lambda a: Post.author_id == a.id,
            name="own_delete",
            description="",
        )

        factory = sessionmaker(bind=safe_get_engine)
        with factory() as sess:
            _seed_data(sess)
            # Alice deleting her own post — allowed
            result = safe_get_or_raise(
                sess,
                Post,
                1,
                actor=actor,
                action="delete",
                registry=registry,
            )
            assert result is not None

            # Alice deleting Bob's post — denied
            with pytest.raises(AuthorizationDenied) as exc_info:
                safe_get_or_raise(
                    sess,
                    Post,
                    3,
                    actor=actor,
                    action="delete",
                    registry=registry,
                )
            assert exc_info.value.action == "delete"
