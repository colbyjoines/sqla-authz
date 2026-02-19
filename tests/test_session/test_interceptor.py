"""Tests for session interceptor — do_orm_execute event hook."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, delete, insert, select, true, update
from sqlalchemy.orm import Session, selectinload, sessionmaker

from sqla_authz.config._config import AuthzConfig
from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.session._interceptor import authorized_sessionmaker, install_interceptor
from tests.conftest import Base, MockActor, Organization, Post, User

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def interceptor_engine():
    """Fresh engine for interceptor tests (isolated from conftest engine)."""
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
# Tests: install_interceptor
# ---------------------------------------------------------------------------


class TestInstallInterceptor:
    """Test install_interceptor hooks into do_orm_execute."""

    def test_intercepts_select_and_applies_authz(self, interceptor_engine, registry) -> None:
        """SELECT queries should have authz filters applied."""
        actor = MockActor(id=1, role="viewer")

        # Policy: only published posts
        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published_only",
            description="",
        )

        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            _seed_data(sess)
            results = sess.execute(select(Post)).scalars().all()
            # Should only get published posts (post1, post3)
            assert len(results) == 2
            assert all(p.is_published for p in results)

    def test_skips_non_select_insert(self, interceptor_engine, registry) -> None:
        """INSERT statements should not be intercepted."""
        actor = MockActor(id=1)

        # Policy that denies everything
        registry.register(
            Post,
            "read",
            lambda a: Post.id < 0,  # impossible condition
            name="deny_all",
            description="",
        )

        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            # Need users table for FK
            sess.execute(insert(User).values(id=1, name="Alice", role="admin"))
            # INSERT should not be intercepted
            sess.execute(
                insert(Post).values(id=99, title="Inserted", is_published=True, author_id=1)
            )
            sess.flush()
            # Verify the post was actually inserted (use skip_authz to read it)
            result = sess.execute(
                select(Post).where(Post.id == 99).execution_options(skip_authz=True)
            ).scalar_one_or_none()
            assert result is not None
            assert result.title == "Inserted"

    def test_skips_non_select_update(self, interceptor_engine, registry) -> None:
        """UPDATE statements should not be intercepted."""
        actor = MockActor(id=1)
        registry.register(Post, "read", lambda a: Post.id < 0, name="deny", description="")

        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            _seed_data(sess)
            # UPDATE should not be intercepted
            sess.execute(update(Post).where(Post.id == 1).values(title="Updated"))
            sess.flush()
            result = sess.execute(
                select(Post).where(Post.id == 1).execution_options(skip_authz=True)
            ).scalar_one()
            assert result.title == "Updated"

    def test_skips_non_select_delete(self, interceptor_engine, registry) -> None:
        """DELETE statements should not be intercepted."""
        actor = MockActor(id=1)
        registry.register(Post, "read", lambda a: Post.id < 0, name="deny", description="")

        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            _seed_data(sess)
            # DELETE should not be intercepted
            sess.execute(delete(Post).where(Post.id == 1))
            sess.flush()
            result = sess.execute(
                select(Post).where(Post.id == 1).execution_options(skip_authz=True)
            ).scalar_one_or_none()
            assert result is None

    def test_skip_authz_execution_option(self, interceptor_engine, registry) -> None:
        """skip_authz=True should bypass interception."""
        actor = MockActor(id=1)

        # Policy that denies everything
        registry.register(Post, "read", lambda a: Post.id < 0, name="deny", description="")

        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            _seed_data(sess)
            # Without skip_authz: should get 0 results
            results_filtered = sess.execute(select(Post)).scalars().all()
            assert len(results_filtered) == 0

            # With skip_authz=True: should get all 3 posts
            results_all = (
                sess.execute(select(Post).execution_options(skip_authz=True)).scalars().all()
            )
            assert len(results_all) == 3

    def test_custom_action_via_execution_options(self, interceptor_engine, registry) -> None:
        """authz_action execution option overrides the default action."""
        actor = MockActor(id=1)

        # "read" allows published; "admin" allows all
        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="read_published",
            description="",
        )
        registry.register(Post, "admin", lambda a: true(), name="admin_all", description="")

        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            _seed_data(sess)
            # Default action "read" — only published
            read_results = sess.execute(select(Post)).scalars().all()
            assert len(read_results) == 2

            # Override action to "admin" — all posts
            admin_results = (
                sess.execute(select(Post).execution_options(authz_action="admin")).scalars().all()
            )
            assert len(admin_results) == 3

    def test_deny_by_default_no_policy(self, interceptor_engine, registry) -> None:
        """No policy registered should result in zero rows (deny by default)."""
        actor = MockActor(id=1)

        # registry is empty — no policies registered
        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            _seed_data(sess)
            results = sess.execute(select(Post)).scalars().all()
            assert len(results) == 0

    def test_actor_provider_called_per_query(self, interceptor_engine, registry) -> None:
        """actor_provider should be called for each query execution."""
        call_count = 0
        current_actor = MockActor(id=1)

        def provider():
            nonlocal call_count
            call_count += 1
            return current_actor

        registry.register(
            Post,
            "read",
            lambda a: Post.author_id == a.id,
            name="own_posts",
            description="",
        )

        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=provider,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            _seed_data(sess)
            sess.execute(select(Post)).scalars().all()
            sess.execute(select(Post)).scalars().all()
            assert call_count == 2

    def test_multiple_entities_in_query(self, interceptor_engine, registry) -> None:
        """Queries with multiple entities should apply policies for each."""
        actor = MockActor(id=1, org_id=1)

        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published_posts",
            description="",
        )
        registry.register(
            User,
            "read",
            lambda a: User.id == a.id,
            name="own_user",
            description="",
        )

        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            _seed_data(sess)
            results = sess.execute(select(Post, User).join(User, Post.author_id == User.id)).all()
            # Only published posts AND only user with id=1
            for post, user in results:
                assert post.is_published
                assert user.id == 1


class TestInstallInterceptorOnMissingPolicyRaise:
    """Test on_missing_policy='raise' configuration."""

    def test_raises_no_policy_error(self, interceptor_engine) -> None:
        """With on_missing_policy='raise', missing policies should raise NoPolicyError."""
        from sqla_authz.exceptions import NoPolicyError

        actor = MockActor(id=1)
        registry = PolicyRegistry()
        config = AuthzConfig(on_missing_policy="raise")

        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            _seed_data(sess)
            with pytest.raises(NoPolicyError):
                sess.execute(select(Post)).scalars().all()


# ---------------------------------------------------------------------------
# Tests: authorized_sessionmaker
# ---------------------------------------------------------------------------


class TestAuthorizedSessionmaker:
    """Test authorized_sessionmaker factory."""

    def test_creates_working_sessionmaker(self, interceptor_engine, registry) -> None:
        """authorized_sessionmaker should return a usable sessionmaker."""
        actor = MockActor(id=1)
        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published",
            description="",
        )

        factory = authorized_sessionmaker(
            bind=interceptor_engine,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            _seed_data(sess)
            results = sess.execute(select(Post)).scalars().all()
            assert len(results) == 2
            assert all(p.is_published for p in results)

    def test_passes_kwargs_to_sessionmaker(self, interceptor_engine, registry) -> None:
        """Extra kwargs should be forwarded to the underlying sessionmaker."""
        actor = MockActor(id=1)
        registry.register(Post, "read", lambda a: true(), name="allow", description="")

        factory = authorized_sessionmaker(
            bind=interceptor_engine,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            expire_on_commit=False,
        )

        with factory() as sess:
            _seed_data(sess)
            results = sess.execute(select(Post)).scalars().all()
            assert len(results) == 3

    def test_skip_authz_works_with_authorized_sessionmaker(
        self, interceptor_engine, registry
    ) -> None:
        """skip_authz should work even with authorized_sessionmaker."""
        actor = MockActor(id=1)
        registry.register(Post, "read", lambda a: Post.id < 0, name="deny", description="")

        factory = authorized_sessionmaker(
            bind=interceptor_engine,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            _seed_data(sess)
            # Filtered: 0 results
            assert len(sess.execute(select(Post)).scalars().all()) == 0
            # skip_authz: all results
            assert (
                len(sess.execute(select(Post).execution_options(skip_authz=True)).scalars().all())
                == 3
            )

    def test_with_custom_config(self, interceptor_engine) -> None:
        """authorized_sessionmaker should accept a custom config."""
        from sqla_authz.exceptions import NoPolicyError

        actor = MockActor(id=1)
        registry = PolicyRegistry()
        config = AuthzConfig(on_missing_policy="raise")

        factory = authorized_sessionmaker(
            bind=interceptor_engine,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            _seed_data(sess)
            with pytest.raises(NoPolicyError):
                sess.execute(select(Post)).scalars().all()

    def test_actor_based_filtering(self, interceptor_engine, registry) -> None:
        """Test real actor-based filtering: user sees only own posts."""
        registry.register(
            Post,
            "read",
            lambda a: Post.author_id == a.id,
            name="own_posts",
            description="",
        )

        # Alice (id=1) should see her own posts
        alice = MockActor(id=1)
        factory = authorized_sessionmaker(
            bind=interceptor_engine,
            actor_provider=lambda: alice,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            _seed_data(sess)
            results = sess.execute(select(Post)).scalars().all()
            assert len(results) == 2  # post1 and post2 belong to Alice
            assert all(p.author_id == 1 for p in results)

        # Bob (id=2) should see only his posts
        bob = MockActor(id=2)
        factory2 = authorized_sessionmaker(
            bind=interceptor_engine,
            actor_provider=lambda: bob,
            action="read",
            registry=registry,
        )

        with factory2() as sess:
            _seed_data(sess)
            results = sess.execute(select(Post)).scalars().all()
            assert len(results) == 1  # only post3 belongs to Bob
            assert results[0].author_id == 2


# ---------------------------------------------------------------------------
# Tests: with_loader_criteria propagation
# ---------------------------------------------------------------------------


class TestLoaderCriteria:
    """Test that authorization filters propagate to relationship loads."""

    def test_selectinload_respects_authz(self, interceptor_engine, registry) -> None:
        """selectinload should apply authz filters to loaded collection relationships."""
        actor = MockActor(id=1, role="admin")

        # User policy: allow all users
        registry.register(
            User,
            "read",
            lambda a: true(),
            name="allow_users",
            description="",
        )
        # Post policy: only published posts
        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published_posts",
            description="",
        )

        # Seed data in a separate session to avoid identity map interference
        plain_factory = sessionmaker(bind=interceptor_engine)
        with plain_factory() as seed_sess:
            _seed_data(seed_sess)
            seed_sess.commit()

        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            # Query Users with selectinload on posts (one-to-many collection)
            results = sess.execute(select(User).options(selectinload(User.posts))).scalars().all()
            # Should get all users (policy allows all)
            assert len(results) == 2  # Alice and Bob

            # The posts collection should be filtered by Post policy
            # Only published posts should appear in the loaded collections
            for user in results:
                for post in user.posts:
                    assert post.is_published, (
                        f"Unpublished post {post.id} loaded for user {user.name}"
                    )

    def test_lazy_load_respects_authz(self, interceptor_engine, registry) -> None:
        """Default lazy loading should respect authz filters via loader criteria."""
        actor = MockActor(id=1, role="admin")

        # User policy: allow all users
        registry.register(
            User,
            "read",
            lambda a: true(),
            name="allow_users",
            description="",
        )
        # Post policy: only published posts
        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published_posts",
            description="",
        )

        # Seed data in a separate session to avoid identity map interference
        plain_factory = sessionmaker(bind=interceptor_engine)
        with plain_factory() as seed_sess:
            _seed_data(seed_sess)
            seed_sess.commit()

        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            # Query Users — lazy load will trigger when accessing .posts
            results = sess.execute(select(User)).scalars().all()
            assert len(results) == 2  # Alice and Bob

            # Access posts via lazy load — with_loader_criteria should filter
            for user in results:
                for post in user.posts:
                    assert post.is_published, (
                        f"Unpublished post {post.id} lazy-loaded for user {user.name}"
                    )

    def test_skip_authz_skips_loader_criteria(self, interceptor_engine, registry) -> None:
        """skip_authz=True should bypass loader criteria as well."""
        actor = MockActor(id=1)

        # Deny-all policies for both models
        registry.register(Post, "read", lambda a: Post.id < 0, name="deny_posts", description="")
        registry.register(User, "read", lambda a: User.id < 0, name="deny_users", description="")

        # Seed data in a separate session
        plain_factory = sessionmaker(bind=interceptor_engine)
        with plain_factory() as seed_sess:
            _seed_data(seed_sess)
            seed_sess.commit()

        factory = sessionmaker(bind=interceptor_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
        )

        with factory() as sess:
            # Without skip_authz: 0 posts
            filtered = sess.execute(select(Post)).scalars().all()
            assert len(filtered) == 0

        # Use a fresh session for skip_authz to avoid identity map issues
        with factory() as sess:
            # With skip_authz: all posts and authors should be accessible
            all_posts = (
                sess.execute(
                    select(Post)
                    .options(selectinload(Post.author))
                    .execution_options(skip_authz=True)
                )
                .scalars()
                .all()
            )
            assert len(all_posts) == 3
            # All authors should be loaded without filtering
            authors = [p.author for p in all_posts if p.author is not None]
            assert len(authors) >= 2  # At least Alice and Bob
