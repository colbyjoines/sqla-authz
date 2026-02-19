"""Hypothesis property tests for sqla-authz authorization invariants."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import Boolean, ForeignKey, Integer, String, create_engine, select
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)

from sqla_authz.compiler._query import authorize_query
from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.testing._actors import MockActor

# ---------------------------------------------------------------------------
# Isolated models for property tests (avoids conftest coupling)
# ---------------------------------------------------------------------------


class PropBase(DeclarativeBase):
    pass


class PropUser(PropBase):
    __tablename__ = "prop_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))


class PropPost(PropBase):
    __tablename__ = "prop_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    is_published: Mapped[bool] = mapped_column(Boolean, default=False)
    author_id: Mapped[int] = mapped_column(ForeignKey("prop_users.id"))

    author: Mapped[PropUser] = relationship("PropUser")


def _make_engine_and_session():
    """Create a fresh in-memory SQLite engine and session."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    PropBase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    return engine, factory()


class TestSoundness:
    """If a row is returned by an authorized query, policy conditions must hold."""

    @given(
        is_published=st.booleans(),
        author_id=st.integers(min_value=1, max_value=100),
        actor_id=st.integers(min_value=1, max_value=100),
    )
    @settings(max_examples=50, deadline=None)
    def test_read_policy_soundness(
        self,
        is_published: bool,
        author_id: int,
        actor_id: int,
    ) -> None:
        """Every returned row satisfies: is_published OR author_id == actor_id."""
        _, sess = _make_engine_and_session()
        try:
            # Seed a user and a post
            user = PropUser(id=author_id, name=f"user-{author_id}")
            sess.merge(user)
            post = PropPost(
                id=1,
                title="test",
                is_published=is_published,
                author_id=author_id,
            )
            sess.merge(post)
            sess.flush()

            # Register policy: published OR own post
            registry = PolicyRegistry()
            registry.register(
                PropPost,
                "read",
                lambda a: (PropPost.is_published == True) | (PropPost.author_id == a.id),
                name="read_policy",
                description="published or own",
            )

            actor = MockActor(id=actor_id)
            stmt = authorize_query(
                select(PropPost),
                actor=actor,
                action="read",
                registry=registry,
            )
            results = sess.execute(stmt).scalars().all()

            # Verify soundness: every returned row satisfies the predicate
            for row in results:
                assert row.is_published or row.author_id == actor_id, (
                    f"Row id={row.id} violates policy: "
                    f"is_published={row.is_published}, author_id={row.author_id}, "
                    f"actor_id={actor_id}"
                )
        finally:
            sess.close()


class TestIdempotence:
    """Applying authorization twice produces equivalent filtering."""

    @given(actor_id=st.integers(min_value=1, max_value=100))
    @settings(max_examples=50, deadline=None)
    def test_double_authorize_same_results(self, actor_id: int) -> None:
        """Authorizing twice returns the same rows as authorizing once."""
        _, sess = _make_engine_and_session()
        try:
            # Seed data
            user = PropUser(id=1, name="author")
            sess.add(user)
            sess.add(PropPost(id=1, title="published", is_published=True, author_id=1))
            sess.add(PropPost(id=2, title="draft", is_published=False, author_id=1))
            sess.flush()

            registry = PolicyRegistry()
            registry.register(
                PropPost,
                "read",
                lambda a: PropPost.is_published == True,
                name="pub",
                description="",
            )

            actor = MockActor(id=actor_id)
            stmt = select(PropPost)
            once = authorize_query(stmt, actor=actor, action="read", registry=registry)
            twice = authorize_query(once, actor=actor, action="read", registry=registry)

            results_once = sess.execute(once).scalars().all()
            results_twice = sess.execute(twice).scalars().all()

            assert len(results_once) == len(results_twice)
            assert {r.id for r in results_once} == {r.id for r in results_twice}
        finally:
            sess.close()


class TestDenyByDefault:
    """No policy registered -> zero rows returned, always."""

    @given(actor_id=st.integers(min_value=1, max_value=1000))
    @settings(max_examples=50, deadline=None)
    def test_no_policy_zero_rows(self, actor_id: int) -> None:
        """Empty registry always produces zero results."""
        _, sess = _make_engine_and_session()
        try:
            user = PropUser(id=1, name="author")
            sess.add(user)
            sess.add(PropPost(id=1, title="published", is_published=True, author_id=1))
            sess.flush()

            registry = PolicyRegistry()  # empty - no policies
            actor = MockActor(id=actor_id)
            stmt = authorize_query(
                select(PropPost),
                actor=actor,
                action="read",
                registry=registry,
            )
            results = sess.execute(stmt).scalars().all()
            assert len(results) == 0, f"Expected zero rows with empty registry, got {len(results)}"
        finally:
            sess.close()


class TestCompleteness:
    """If a row satisfies policy conditions, it must be returned."""

    @given(
        is_published=st.booleans(),
        author_id=st.integers(min_value=1, max_value=100),
        actor_id=st.integers(min_value=1, max_value=100),
    )
    @settings(max_examples=50, deadline=None)
    def test_matching_rows_are_returned(
        self,
        is_published: bool,
        author_id: int,
        actor_id: int,
    ) -> None:
        """If is_published OR author_id == actor_id, the row must be returned."""
        _, sess = _make_engine_and_session()
        try:
            user = PropUser(id=author_id, name=f"user-{author_id}")
            sess.merge(user)
            post = PropPost(
                id=1,
                title="test",
                is_published=is_published,
                author_id=author_id,
            )
            sess.merge(post)
            sess.flush()

            registry = PolicyRegistry()
            registry.register(
                PropPost,
                "read",
                lambda a: (PropPost.is_published == True) | (PropPost.author_id == a.id),
                name="read_policy",
                description="published or own",
            )

            actor = MockActor(id=actor_id)
            stmt = authorize_query(
                select(PropPost),
                actor=actor,
                action="read",
                registry=registry,
            )
            results = sess.execute(stmt).scalars().all()
            result_ids = {r.id for r in results}

            should_be_returned = is_published or (author_id == actor_id)
            if should_be_returned:
                assert 1 in result_ids, (
                    f"Row should be returned: is_published={is_published}, "
                    f"author_id={author_id}, actor_id={actor_id}"
                )
            else:
                assert 1 not in result_ids, (
                    f"Row should NOT be returned: is_published={is_published}, "
                    f"author_id={author_id}, actor_id={actor_id}"
                )
        finally:
            sess.close()
