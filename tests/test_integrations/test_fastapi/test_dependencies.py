"""Tests for FastAPI dependencies (AuthzDep)."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import Boolean, Integer, String, create_engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)

from sqla_authz.integrations.fastapi._dependencies import (
    AuthzDep,
    get_actor,
    get_session,
)
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


class Document(Base):
    """Model with a non-'id' primary key column."""

    __tablename__ = "documents"

    uuid: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    is_public: Mapped[bool] = mapped_column(Boolean, default=False)


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
def seeded_session_with_docs(db_session: Session) -> Session:
    """Seed the database with test articles and documents."""
    db_session.add_all(
        [
            Article(id=1, title="Published 1", is_published=True, owner_id=1),
            Article(id=2, title="Draft", is_published=False, owner_id=1),
            Article(id=3, title="Published 2", is_published=True, owner_id=2),
            Document(uuid="abc-123", title="Public Doc", is_public=True),
            Document(uuid="def-456", title="Private Doc", is_public=False),
        ]
    )
    db_session.flush()
    return db_session


@pytest.fixture()
def app_with_policies(seeded_session: Session, registry: PolicyRegistry) -> FastAPI:
    """Build a FastAPI app with policies and routes for testing."""
    registry.register(
        Article,
        "read",
        lambda actor: Article.is_published == True,  # noqa: E712
        name="read_published",
        description="Viewers can read published articles",
    )

    app = FastAPI()
    install_error_handlers(app)

    _current_actor = Actor(id=1, role="viewer")

    app.dependency_overrides[get_actor] = lambda: _current_actor
    app.dependency_overrides[get_session] = lambda: seeded_session

    @app.get("/articles")
    async def list_articles(
        articles: list[Article] = AuthzDep(Article, "read", registry=registry),  # type: ignore[assignment]
    ) -> list[dict]:
        return [{"id": a.id, "title": a.title} for a in articles]

    @app.get("/articles/{article_id}")
    async def get_article(
        article: Article = AuthzDep(Article, "read", id_param="article_id", registry=registry),  # type: ignore[assignment]
    ) -> dict:
        return {"id": article.id, "title": article.title}

    return app


@pytest.fixture()
def client(app_with_policies: FastAPI) -> TestClient:
    return TestClient(app_with_policies)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


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
        app.dependency_overrides[get_actor] = lambda: Actor(id=1)
        app.dependency_overrides[get_session] = lambda: sess

        @app.get("/articles")
        async def list_articles(
            articles: list[Article] = AuthzDep(Article, "read", registry=deny_registry),  # type: ignore[assignment]
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
        response = client.get("/articles/2")
        assert response.status_code == 404


class TestAuthzDepCustomRegistry:
    def test_uses_custom_registry(self, seeded_session: Session) -> None:
        """AuthzDep can use a per-dependency registry override."""
        custom_registry = PolicyRegistry()
        custom_registry.register(
            Article,
            "read",
            lambda actor: Article.id > 0,
            name="allow_all",
            description="Allow all",
        )

        app = FastAPI()
        app.dependency_overrides[get_actor] = lambda: Actor(id=1)
        app.dependency_overrides[get_session] = lambda: seeded_session

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


# ---------------------------------------------------------------------------
# pk_column tests
# ---------------------------------------------------------------------------


class TestPkColumn:
    """AuthzDep supports configurable pk_column parameter."""

    def test_custom_pk_column(self, seeded_session_with_docs: Session) -> None:
        """Models with non-id PK work when pk_column is specified."""
        registry = PolicyRegistry()
        registry.register(
            Document,
            "read",
            lambda actor: Document.is_public == True,  # noqa: E712
            name="read_public",
            description="Read public documents",
        )

        app = FastAPI()
        app.dependency_overrides[get_actor] = lambda: Actor(id=1)
        app.dependency_overrides[get_session] = lambda: seeded_session_with_docs

        @app.get("/documents/{doc_uuid}")
        async def get_document(
            doc: Document = AuthzDep(  # type: ignore[assignment]
                Document, "read", id_param="doc_uuid", pk_column="uuid", registry=registry
            ),
        ) -> dict:
            return {"uuid": doc.uuid, "title": doc.title}

        client = TestClient(app)
        response = client.get("/documents/abc-123")
        assert response.status_code == 200
        data = response.json()
        assert data["uuid"] == "abc-123"
        assert data["title"] == "Public Doc"

    def test_custom_pk_column_404_when_not_authorized(
        self, seeded_session_with_docs: Session
    ) -> None:
        """pk_column lookup returns 404 when item is not authorized."""
        registry = PolicyRegistry()
        registry.register(
            Document,
            "read",
            lambda actor: Document.is_public == True,  # noqa: E712
            name="read_public",
            description="Read public documents",
        )

        app = FastAPI()
        app.dependency_overrides[get_actor] = lambda: Actor(id=1)
        app.dependency_overrides[get_session] = lambda: seeded_session_with_docs

        @app.get("/documents/{doc_uuid}")
        async def get_document(
            doc: Document = AuthzDep(  # type: ignore[assignment]
                Document, "read", id_param="doc_uuid", pk_column="uuid", registry=registry
            ),
        ) -> dict:
            return {"uuid": doc.uuid, "title": doc.title}

        client = TestClient(app)
        # Private doc should return 404
        response = client.get("/documents/def-456")
        assert response.status_code == 404

    def test_default_pk_column_is_id(self, client: TestClient) -> None:
        """Default pk_column='id' works for standard integer PKs."""
        response = client.get("/articles/1")
        assert response.status_code == 200
        assert response.json()["id"] == 1

    def test_custom_pk_column_collection(self, seeded_session_with_docs: Session) -> None:
        """Collection endpoints work with models that have custom PK columns."""
        registry = PolicyRegistry()
        registry.register(
            Document,
            "read",
            lambda actor: Document.is_public == True,  # noqa: E712
            name="read_public",
            description="Read public documents",
        )

        app = FastAPI()
        app.dependency_overrides[get_actor] = lambda: Actor(id=1)
        app.dependency_overrides[get_session] = lambda: seeded_session_with_docs

        @app.get("/documents")
        async def list_documents(
            docs: list[Document] = AuthzDep(Document, "read", registry=registry),  # type: ignore[assignment]
        ) -> list[dict]:
            return [{"uuid": d.uuid, "title": d.title} for d in docs]

        client = TestClient(app)
        response = client.get("/documents")
        assert response.status_code == 200
        data = response.json()
        # Only the public doc
        assert len(data) == 1
        assert data[0]["title"] == "Public Doc"


class TestAsyncSessionSupport:
    """AuthzDep handles async sessions correctly."""

    def test_sync_session_works(self, client: TestClient) -> None:
        """Sync sessions work with AuthzDep."""
        response = client.get("/articles")
        assert response.status_code == 200
        assert len(response.json()) == 2

    def test_async_session_detected(
        self, seeded_session: Session, registry: PolicyRegistry
    ) -> None:
        """When an AsyncSession is provided, await is used for execute."""
        registry.register(
            Article,
            "read",
            lambda actor: Article.is_published == True,  # noqa: E712
            name="read_published",
            description="Viewers can read published articles",
        )

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [
            Article(id=1, title="Mocked", is_published=True, owner_id=1)
        ]

        mock_async_session = AsyncMock()
        mock_async_session.execute = AsyncMock(return_value=mock_result)

        app = FastAPI()
        app.dependency_overrides[get_actor] = lambda: Actor(id=1)
        app.dependency_overrides[get_session] = lambda: mock_async_session

        @app.get("/articles")
        async def list_articles(
            articles: list[Article] = AuthzDep(Article, "read", registry=registry),  # type: ignore[assignment]
        ) -> list[dict]:
            return [{"id": a.id, "title": a.title} for a in articles]

        with patch(
            "sqla_authz.integrations.fastapi._dependencies._is_async_session",
            return_value=True,
        ):
            client = TestClient(app)
            response = client.get("/articles")
            assert response.status_code == 200
            data = response.json()
            assert len(data) == 1
            assert data[0]["title"] == "Mocked"

        mock_async_session.execute.assert_awaited()


class TestDependencyInjection:
    """Sentinel dependency functions for DI-based configuration."""

    def test_get_actor_raises_not_implemented(self) -> None:
        """get_actor sentinel raises NotImplementedError when not overridden."""
        mock_request = MagicMock(spec=Request)
        with pytest.raises(NotImplementedError, match="Override get_actor"):
            get_actor(mock_request)

    def test_get_session_raises_not_implemented(self) -> None:
        """get_session sentinel raises NotImplementedError when not overridden."""
        mock_request = MagicMock(spec=Request)
        with pytest.raises(NotImplementedError, match="Override get_session"):
            get_session(mock_request)

    def test_sentinels_are_importable(self) -> None:
        """Sentinel functions are available via public imports."""
        from sqla_authz.integrations.fastapi import get_actor, get_session

        assert callable(get_actor)
        assert callable(get_session)

    def test_dependency_overrides_work(self, seeded_session: Session) -> None:
        """dependency_overrides[get_actor] and [get_session] work with AuthzDep."""
        reg = PolicyRegistry()
        reg.register(
            Article,
            "read",
            lambda actor: Article.is_published == True,  # noqa: E712
            name="read_published",
            description="Read published",
        )

        app = FastAPI()

        _actor = Actor(id=1, role="viewer")

        app.dependency_overrides[get_actor] = lambda: _actor
        app.dependency_overrides[get_session] = lambda: seeded_session

        @app.get("/articles")
        async def list_articles(
            articles: list[Article] = AuthzDep(Article, "read", registry=reg),  # type: ignore[assignment]
        ) -> list[dict]:
            return [{"id": a.id, "title": a.title} for a in articles]

        @app.get("/articles/{article_id}")
        async def get_article(
            article: Article = AuthzDep(  # type: ignore[assignment]
                Article, "read", id_param="article_id", registry=reg
            ),
        ) -> dict:
            return {"id": article.id, "title": article.title}

        client = TestClient(app)

        # Collection endpoint
        response = client.get("/articles")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2  # only published
        titles = {d["title"] for d in data}
        assert "Published 1" in titles
        assert "Draft" not in titles

        # Single-item endpoint
        response = client.get("/articles/1")
        assert response.status_code == 200
        assert response.json()["title"] == "Published 1"

        # Denied item returns 404
        response = client.get("/articles/2")
        assert response.status_code == 404

    def test_neither_configured_raises(self) -> None:
        """When get_actor/get_session are not overridden, NotImplementedError surfaces."""
        reg = PolicyRegistry()
        reg.register(
            Article,
            "read",
            lambda actor: Article.is_published == True,  # noqa: E712
            name="read_published",
            description="Read published",
        )

        app = FastAPI()

        @app.get("/articles")
        async def list_articles(
            articles: list[Article] = AuthzDep(Article, "read", registry=reg),  # type: ignore[assignment]
        ) -> list[dict]:
            return [{"id": a.id, "title": a.title} for a in articles]

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/articles")
        assert response.status_code == 500
