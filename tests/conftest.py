"""Shared test fixtures for sqla-authz tests."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from sqlalchemy import Boolean, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

# ---------------------------------------------------------------------------
# Test models
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)

    parent: Mapped[Organization | None] = relationship(
        "Organization", remote_side="Organization.id", uselist=False
    )
    users: Mapped[list[User]] = relationship("User", back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(50), default="viewer")
    org_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)

    organization: Mapped[Organization | None] = relationship(
        "Organization", back_populates="users"
    )
    posts: Mapped[list[Post]] = relationship("Post", back_populates="author")


class Post(Base):
    __tablename__ = "posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    is_published: Mapped[bool] = mapped_column(Boolean, default=False)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    author: Mapped[User] = relationship("User", back_populates="posts")
    tags: Mapped[list[Tag]] = relationship("Tag", secondary="post_tags", back_populates="posts")


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50))
    visibility: Mapped[str] = mapped_column(String(20), default="public")

    posts: Mapped[list[Post]] = relationship("Post", secondary="post_tags", back_populates="tags")


from sqlalchemy import Column, Table  # noqa: E402

post_tags = Table(
    "post_tags",
    Base.metadata,
    Column("post_id", Integer, ForeignKey("posts.id"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id"), primary_key=True),
)


# ---------------------------------------------------------------------------
# MockActor — satisfies ActorLike protocol
# ---------------------------------------------------------------------------


@dataclass
class MockActor:
    """Test actor that satisfies ActorLike protocol."""

    id: int | str
    role: str = "viewer"
    org_id: int | None = None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine():
    """Create an in-memory SQLite engine with all tables."""
    eng = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def session(engine):
    """Provide a transactional session that rolls back after each test."""
    factory = sessionmaker(bind=engine)
    sess = factory()
    try:
        yield sess
    finally:
        sess.rollback()
        sess.close()


@pytest.fixture()
def sample_data(session: Session) -> dict[str, list]:
    """Seed the database with sample data for testing."""
    org = Organization(id=1, name="Acme Corp")
    session.add(org)

    alice = User(id=1, name="Alice", role="admin", org_id=1)
    bob = User(id=2, name="Bob", role="editor", org_id=1)
    charlie = User(id=3, name="Charlie", role="viewer", org_id=None)
    session.add_all([alice, bob, charlie])

    tag_public = Tag(id=1, name="python", visibility="public")
    tag_private = Tag(id=2, name="internal", visibility="private")
    session.add_all([tag_public, tag_private])

    post1 = Post(id=1, title="Public Post", is_published=True, author_id=1)
    post2 = Post(id=2, title="Draft Post", is_published=False, author_id=1)
    post3 = Post(id=3, title="Bob's Post", is_published=True, author_id=2)
    post1.tags.append(tag_public)
    post2.tags.append(tag_private)
    session.add_all([post1, post2, post3])

    session.flush()
    return {
        "users": [alice, bob, charlie],
        "posts": [post1, post2, post3],
        "tags": [tag_public, tag_private],
        "organizations": [org],
    }
