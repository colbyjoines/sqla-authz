"""Tests for FastAPI dependencies (AuthzDep + configure_authz)."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Boolean, Integer, String, create_engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)

from sqla_authz.integrations.fastapi._dependencies import AuthzDep, configure_authz
from sqla_authz.integrations.fastapi._errors import install_error_handlers
from sqla_authz.policy._registry import PolicyRegistry

# ---------------------------------------------------------------------------
# Test-local models (isolated from conftest models)
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class Article(Base):
    __tablename__ = "articles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    is_published: Mapped[bool] = mapped_column(Boolean, default=False)
    owner_id: Mapped[int] = mapped_column(Integer)


# ---------------------------------------------------------------------------
# Test actor
# ---------------------------------------------------------------------------


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
def db_session(db_engine):
    factory = sessionmaker(bind=db_engine)
    sess = factory()
    try:
        yield sess
    finally:
        sess.rollback()
        sess.close()


@pytest.fixture()
def registry() -> PolicyRegistry:
    return PolicyRegistry()


@pytest.fixture()
def seeded_session(db_session: Session) -> Session:
    """Seed the database with test articles."""
    db_session.add_all(
        [
            Article(id=1, title="Published 1", is_published=True, owner_id=1),
            Article(id=2, title="Draft", is_published=False, owner_id=1),
            Article(id=3, title="Published 2", is_published=True, owner_id=2),
        ]
    )
    db_session.flush()
    return db_session


@pytest.fixture()
def app_with_policies(seeded_session: Session, registry: PolicyRegistry) -> FastAPI:
    """Build a FastAPI app with policies and routes for testing."""
    # Register a policy: viewers see only published articles
    registry.register(
        Article,
        "read",
        lambda actor: Article.is_published == True,  # noqa: E712
        name="read_published",
        description="Viewers can read published articles",
    )

    app = FastAPI()
    install_error_handlers(app)

    # Configure authz - actor_provider and session_provider are callables
    # that receive a Request and return actor / session
    _current_actor = Actor(id=1, role="viewer")

    configure_authz(
        app=app,
        get_actor=lambda request: _current_actor,
        get_session=lambda request: seeded_session,
        registry=registry,
    )

    @app.get("/articles")
    async def list_articles(
        articles: list[Article] = AuthzDep(Article, "read"),  # type: ignore[assignment]
    ) -> list[dict]:
        return [{"id": a.id, "title": a.title} for a in articles]

    @app.get("/articles/{article_id}")
    async def get_article(
        article: Article = AuthzDep(Article, "read", id_param="article_id"),  # type: ignore[assignment]
    ) -> dict:
        return {"id": article.id, "title": article.title}

    return app


@pytest.fixture()
def client(app_with_policies: FastAPI) -> TestClient:
    return TestClient(app_with_policies)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestConfigureAuthz:
    def test_stores_providers(self, seeded_session: Session, registry: PolicyRegistry) -> None:
        """configure_authz stores the provider functions."""
        app = FastAPI()

        def actor_fn(request):
            return Actor(id=1)

        def session_fn(request):
            return seeded_session

        configure_authz(
            app=app,
            get_actor=actor_fn,
            get_session=session_fn,
            registry=registry,
        )

        # The state should be retrievable from app.state
        assert app.state.sqla_authz_get_actor is actor_fn
        assert app.state.sqla_authz_get_session is session_fn
        assert app.state.sqla_authz_registry is registry

    def test_defaults_registry_to_none(self, seeded_session: Session) -> None:
        """When no registry is passed, it defaults to None (use global)."""
        app = FastAPI()
        configure_authz(
            app=app,
            get_actor=lambda r: Actor(id=1),
            get_session=lambda r: seeded_session,
        )
        assert app.state.sqla_authz_registry is None


class TestAuthzDepCollection:
    def test_returns_list(self, client: TestClient) -> None:
        """Collection endpoint returns a list of items."""
        response = client.get("/articles")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_authorization_filters_results(self, client: TestClient) -> None:
        """Only authorized (published) articles are returned."""
        response = client.get("/articles")
        data = response.json()
        # 2 published out of 3 total
        assert len(data) == 2
        titles = {d["title"] for d in data}
        assert "Published 1" in titles
        assert "Published 2" in titles
        assert "Draft" not in titles

    def test_returns_empty_list_when_no_results(self, registry: PolicyRegistry, db_engine) -> None:
        """Returns empty list when no rows match the policy."""
        # Use a deny-all policy (no policy registered = WHERE FALSE)
        deny_registry = PolicyRegistry()

        engine = create_engine(
            "sqlite:///:memory:",
            echo=False,
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        sess = factory()
        sess.add(Article(id=1, title="X", is_published=True, owner_id=1))
        sess.flush()

        app = FastAPI()
        configure_authz(
            app=app,
            get_actor=lambda r: Actor(id=1),
            get_session=lambda r: sess,
            registry=deny_registry,
        )

        @app.get("/articles")
        async def list_articles(
            articles: list[Article] = AuthzDep(Article, "read"),  # type: ignore[assignment]
        ) -> list[dict]:
            return [{"id": a.id, "title": a.title} for a in articles]

        client = TestClient(app)
        response = client.get("/articles")
        assert response.status_code == 200
        assert response.json() == []


class TestAuthzDepSingleItem:
    def test_returns_single_item(self, client: TestClient) -> None:
        """Single-item endpoint returns the item by PK."""
        response = client.get("/articles/1")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == 1
        assert data["title"] == "Published 1"

    def test_returns_404_when_not_found(self, client: TestClient) -> None:
        """Returns 404 when item doesn't exist."""
        response = client.get("/articles/999")
        assert response.status_code == 404

    def test_returns_404_when_not_authorized(self, client: TestClient) -> None:
        """Returns 404 when item exists but is not authorized (draft)."""
        # Article 2 is a draft, not visible to viewer
        response = client.get("/articles/2")
        assert response.status_code == 404


class TestAuthzDepCustomRegistry:
    def test_uses_custom_registry(self, seeded_session: Session) -> None:
        """AuthzDep can use a per-dependency registry override."""
        custom_registry = PolicyRegistry()
        # Register a policy that allows ALL articles
        custom_registry.register(
            Article,
            "read",
            lambda actor: Article.id > 0,
            name="allow_all",
            description="Allow all",
        )

        # App-level registry denies everything (empty)
        app_registry = PolicyRegistry()

        app = FastAPI()
        configure_authz(
            app=app,
            get_actor=lambda r: Actor(id=1),
            get_session=lambda r: seeded_session,
            registry=app_registry,
        )

        @app.get("/articles")
        async def list_articles(
            articles: list[Article] = AuthzDep(  # type: ignore[assignment]
                Article, "read", registry=custom_registry
            ),
        ) -> list[dict]:
            return [{"id": a.id, "title": a.title} for a in articles]

        client = TestClient(app)
        response = client.get("/articles")
        assert response.status_code == 200
        # Custom registry allows all 3 articles
        assert len(response.json()) == 3
