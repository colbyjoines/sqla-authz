"""Benchmark fixtures — models, registries, and populated sessions."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from sqlalchemy import Boolean, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)

from sqla_authz.policy._registry import PolicyRegistry

# ---------------------------------------------------------------------------
# Benchmark-local models (separate DeclarativeBase to avoid conflicts)
# ---------------------------------------------------------------------------


class BenchBase(DeclarativeBase):
    pass


class BenchOrg(BenchBase):
    __tablename__ = "bench_orgs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))

    authors: Mapped[list[BenchAuthor]] = relationship("BenchAuthor", back_populates="organization")


class BenchAuthor(BenchBase):
    __tablename__ = "bench_authors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    org_id: Mapped[int | None] = mapped_column(ForeignKey("bench_orgs.id"), nullable=True)

    organization: Mapped[BenchOrg | None] = relationship("BenchOrg", back_populates="authors")
    posts: Mapped[list[BenchPost]] = relationship("BenchPost", back_populates="author")


class BenchPost(BenchBase):
    __tablename__ = "bench_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    is_published: Mapped[bool] = mapped_column(Boolean, default=False)
    author_id: Mapped[int | None] = mapped_column(ForeignKey("bench_authors.id"), nullable=True)

    author: Mapped[BenchAuthor | None] = relationship("BenchAuthor", back_populates="posts")


# ---------------------------------------------------------------------------
# MockActor for benchmarks
# ---------------------------------------------------------------------------


@dataclass
class BenchActor:
    """Actor satisfying ActorLike protocol for benchmarks."""

    id: int
    org_id: int | None = None


# ---------------------------------------------------------------------------
# Engine / session fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def bench_engine():
    """In-memory SQLite engine with benchmark tables."""
    eng = create_engine("sqlite:///:memory:", echo=False)
    BenchBase.metadata.create_all(eng)
    return eng


@pytest.fixture(scope="module")
def bench_session_factory(bench_engine):
    """Session factory bound to the benchmark engine."""
    return sessionmaker(bind=bench_engine)


@pytest.fixture()
def bench_session(bench_session_factory):
    """Fresh session per test (rolls back)."""
    sess = bench_session_factory()
    try:
        yield sess
    finally:
        sess.rollback()
        sess.close()


# ---------------------------------------------------------------------------
# Populated sessions with varying row counts
# ---------------------------------------------------------------------------


def _seed_posts(engine, count: int) -> None:
    """Bulk-insert *count* BenchPost rows with associated authors."""
    BenchBase.metadata.create_all(engine)
    session_cls = sessionmaker(bind=engine)
    sess = session_cls()
    try:
        # Create a few authors to reference
        authors = [BenchAuthor(id=i, name=f"Author {i}", org_id=None) for i in range(1, 11)]
        sess.add_all(authors)
        sess.flush()

        # Bulk insert posts via core for speed
        table = BenchPost.__table__
        rows = [
            {
                "id": i,
                "title": f"Post {i}",
                "is_published": i % 2 == 0,
                "author_id": (i % 10) + 1,
            }
            for i in range(1, count + 1)
        ]
        sess.execute(table.insert(), rows)
        sess.commit()
    except Exception:
        sess.rollback()
        raise
    finally:
        sess.close()


@pytest.fixture(scope="module")
def populated_engine_1k():
    """SQLite engine pre-loaded with 1,000 posts."""
    eng = create_engine("sqlite:///:memory:", echo=False)
    _seed_posts(eng, 1_000)
    return eng


@pytest.fixture(scope="module")
def populated_engine_10k():
    """SQLite engine pre-loaded with 10,000 posts."""
    eng = create_engine("sqlite:///:memory:", echo=False)
    _seed_posts(eng, 10_000)
    return eng


@pytest.fixture(scope="module")
def populated_engine_100k():
    """SQLite engine pre-loaded with 100,000 posts."""
    eng = create_engine("sqlite:///:memory:", echo=False)
    _seed_posts(eng, 100_000)
    return eng


@pytest.fixture()
def populated_session_1k(populated_engine_1k):
    """Session over 1K-row database."""
    sess = sessionmaker(bind=populated_engine_1k)()
    try:
        yield sess
    finally:
        sess.close()


@pytest.fixture()
def populated_session_10k(populated_engine_10k):
    """Session over 10K-row database."""
    sess = sessionmaker(bind=populated_engine_10k)()
    try:
        yield sess
    finally:
        sess.close()


@pytest.fixture()
def populated_session_100k(populated_engine_100k):
    """Session over 100K-row database."""
    sess = sessionmaker(bind=populated_engine_100k)()
    try:
        yield sess
    finally:
        sess.close()


# ---------------------------------------------------------------------------
# Actor fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_actor() -> BenchActor:
    """Default benchmark actor."""
    return BenchActor(id=1, org_id=1)


# ---------------------------------------------------------------------------
# Registry fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def simple_registry() -> PolicyRegistry:
    """Registry with a single simple attribute policy."""
    reg = PolicyRegistry()
    reg.register(
        BenchPost,
        "read",
        lambda actor: BenchPost.is_published == True,  # noqa: E712
        name="published_only",
        description="Allow reading published posts",
    )
    return reg


@pytest.fixture()
def complex_registry() -> PolicyRegistry:
    """Registry with OR + relationship traversal policy."""
    reg = PolicyRegistry()
    # Policy 1: published posts
    reg.register(
        BenchPost,
        "read",
        lambda actor: BenchPost.is_published == True,  # noqa: E712
        name="published_only",
        description="Allow reading published posts",
    )
    # Policy 2: own posts (requires relationship traversal)
    reg.register(
        BenchPost,
        "read",
        lambda actor: BenchPost.author.has(BenchAuthor.id == actor.id),
        name="own_posts",
        description="Allow reading own posts",
    )
    return reg


def _make_multi_registry(n: int) -> PolicyRegistry:
    """Create a registry with *n* policies for BenchPost read."""
    reg = PolicyRegistry()
    for i in range(n):
        reg.register(
            BenchPost,
            "read",
            lambda actor, _i=i: BenchPost.is_published == True,  # noqa: E712
            name=f"policy_{i}",
            description=f"Policy number {i}",
        )
    return reg


@pytest.fixture()
def multi_registry_5() -> PolicyRegistry:
    """Registry with 5 policies."""
    return _make_multi_registry(5)


@pytest.fixture()
def multi_registry_10() -> PolicyRegistry:
    """Registry with 10 policies."""
    return _make_multi_registry(10)


# ---------------------------------------------------------------------------
# Relationship traversal fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def relationship_engine():
    """Engine with orgs, authors, posts for relationship benchmarks."""
    eng = create_engine("sqlite:///:memory:", echo=False)
    BenchBase.metadata.create_all(eng)
    sess = sessionmaker(bind=eng)()
    try:
        orgs = [BenchOrg(id=i, name=f"Org {i}") for i in range(1, 6)]
        sess.add_all(orgs)
        sess.flush()

        authors = [BenchAuthor(id=i, name=f"Author {i}", org_id=(i % 5) + 1) for i in range(1, 51)]
        sess.add_all(authors)
        sess.flush()

        table = BenchPost.__table__
        rows = [
            {
                "id": i,
                "title": f"Post {i}",
                "is_published": i % 2 == 0,
                "author_id": (i % 50) + 1,
            }
            for i in range(1, 1001)
        ]
        sess.execute(table.insert(), rows)
        sess.commit()
    except Exception:
        sess.rollback()
        raise
    finally:
        sess.close()
    return eng


@pytest.fixture()
def relationship_session(relationship_engine):
    """Session for relationship traversal benchmarks."""
    sess = sessionmaker(bind=relationship_engine)()
    try:
        yield sess
    finally:
        sess.close()
