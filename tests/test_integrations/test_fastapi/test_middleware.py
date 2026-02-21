"""Tests for FastAPI interceptor middleware (install_authz_interceptor)."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from sqlalchemy import Boolean, Integer, String, create_engine, select
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    sessionmaker,
)

from sqla_authz.integrations.fastapi._middleware import install_authz_interceptor
from sqla_authz.policy._registry import PolicyRegistry

# ---------------------------------------------------------------------------
# Test-local models
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class Post(Base):
    __tablename__ = "mw_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    is_published: Mapped[bool] = mapped_column(Boolean, default=False)
    author_id: Mapped[int] = mapped_column(Integer)


@dataclass
class Actor:
    id: int
    role: str = "viewer"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture()
def registry() -> PolicyRegistry:
    reg = PolicyRegistry()
    reg.register(
        Post,
        "read",
        lambda actor: Post.is_published == True,  # noqa: E712
        name="read_published",
        description="Viewers can read published posts",
    )
    return reg


@pytest.fixture()
def session_factory(db_engine):
    return sessionmaker(bind=db_engine)


@pytest.fixture()
def seeded_factory(session_factory) -> sessionmaker:
    """Seed the database and return the factory."""
    sess = session_factory()
    sess.add_all(
        [
            Post(id=1, title="Published Post", is_published=True, author_id=1),
            Post(id=2, title="Draft Post", is_published=False, author_id=1),
            Post(id=3, title="Another Published", is_published=True, author_id=2),
        ]
    )
    sess.commit()
    sess.close()
    return session_factory


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestInstallAuthzInterceptor:
    """Tests for install_authz_interceptor wrapper."""

    def test_queries_auto_filtered(
        self, seeded_factory: sessionmaker, registry: PolicyRegistry
    ) -> None:
        """install_authz_interceptor applies authorization to all queries."""
        current_actor = Actor(id=1)

        install_authz_interceptor(
            seeded_factory,
            actor_provider=lambda: current_actor,
            action="read",
            registry=registry,
        )

        with seeded_factory() as session:
            posts = session.execute(select(Post)).scalars().all()

        # Only published posts should be returned (2 out of 3)
        assert len(posts) == 2
        titles = {p.title for p in posts}
        assert "Published Post" in titles
        assert "Another Published" in titles
        assert "Draft Post" not in titles

    def test_action_override(self, seeded_factory: sessionmaker, registry: PolicyRegistry) -> None:
        """execution_options(authz_action=...) overrides the default action."""
        # Register a separate "admin_read" policy that allows all
        registry.register(
            Post,
            "admin_read",
            lambda actor: Post.id > 0,
            name="admin_read_all",
            description="Admin can read all posts",
        )

        current_actor = Actor(id=1)

        install_authz_interceptor(
            seeded_factory,
            actor_provider=lambda: current_actor,
            action="read",
            registry=registry,
        )

        with seeded_factory() as session:
            # Override action to "admin_read" via execution_options
            stmt = select(Post).execution_options(authz_action="admin_read")
            posts = session.execute(stmt).scalars().all()

        # admin_read allows all 3 posts
        assert len(posts) == 3

    def test_skip_authz_works(
        self, seeded_factory: sessionmaker, registry: PolicyRegistry
    ) -> None:
        """skip_authz=True bypasses the interceptor."""
        current_actor = Actor(id=1)

        install_authz_interceptor(
            seeded_factory,
            actor_provider=lambda: current_actor,
            action="read",
            registry=registry,
        )

        with seeded_factory() as session:
            # Use skip_authz to bypass authorization
            stmt = select(Post).execution_options(skip_authz=True)
            posts = session.execute(stmt).scalars().all()

        # All 3 posts should be returned (no filtering)
        assert len(posts) == 3

    def test_default_action_is_read(
        self, seeded_factory: sessionmaker, registry: PolicyRegistry
    ) -> None:
        """Default action parameter is 'read'."""
        current_actor = Actor(id=1)

        # Don't pass action -- should default to "read"
        install_authz_interceptor(
            seeded_factory,
            actor_provider=lambda: current_actor,
            registry=registry,
        )

        with seeded_factory() as session:
            posts = session.execute(select(Post)).scalars().all()

        # Only published (read policy) should be returned
        assert len(posts) == 2

    def test_uses_default_registry_when_none(self, seeded_factory: sessionmaker) -> None:
        """When registry=None, falls back to the global default registry."""
        from sqla_authz.policy._registry import get_default_registry

        default_reg = get_default_registry()

        # Register on the default registry temporarily
        default_reg.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="default_read",
            description="Default read policy",
        )

        try:
            current_actor = Actor(id=1)
            install_authz_interceptor(
                seeded_factory,
                actor_provider=lambda: current_actor,
                action="read",
                # registry=None (default)
            )

            with seeded_factory() as session:
                posts = session.execute(select(Post)).scalars().all()

            assert len(posts) == 2
        finally:
            # Clean up default registry
            default_reg.clear()

    def test_custom_config(self, seeded_factory: sessionmaker, registry: PolicyRegistry) -> None:
        """Custom AuthzConfig can be passed to the interceptor."""
        from sqla_authz.config._config import AuthzConfig

        config = AuthzConfig(on_missing_policy="deny")
        current_actor = Actor(id=1)

        install_authz_interceptor(
            seeded_factory,
            actor_provider=lambda: current_actor,
            action="read",
            registry=registry,
            config=config,
        )

        with seeded_factory() as session:
            posts = session.execute(select(Post)).scalars().all()

        # Should work normally with custom config
        assert len(posts) == 2
