"""Tests for FastAPI dependencies (AuthzDep + configure_authz)."""

from __future__ import annotations

import warnings
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
    configure_authz,
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

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
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

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
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
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
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
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
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
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
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


# ---------------------------------------------------------------------------
# New test classes for Plan 05 features
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
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            configure_authz(
                app=app,
                get_actor=lambda r: Actor(id=1),
                get_session=lambda r: seeded_session_with_docs,
                registry=registry,
            )

        @app.get("/documents/{doc_uuid}")
        async def get_document(
            doc: Document = AuthzDep(  # type: ignore[assignment]
                Document, "read", id_param="doc_uuid", pk_column="uuid"
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
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            configure_authz(
                app=app,
                get_actor=lambda r: Actor(id=1),
                get_session=lambda r: seeded_session_with_docs,
                registry=registry,
            )

        @app.get("/documents/{doc_uuid}")
        async def get_document(
            doc: Document = AuthzDep(  # type: ignore[assignment]
                Document, "read", id_param="doc_uuid", pk_column="uuid"
            ),
        ) -> dict:
            return {"uuid": doc.uuid, "title": doc.title}

        client = TestClient(app)
        # Private doc should return 404
        response = client.get("/documents/def-456")
        assert response.status_code == 404

    def test_default_pk_column_is_id(self, client: TestClient) -> None:
        """Default pk_column='id' maintains backward compat (implicit via existing tests)."""
        # Existing app_with_policies uses default pk_column (id)
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
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            configure_authz(
                app=app,
                get_actor=lambda r: Actor(id=1),
                get_session=lambda r: seeded_session_with_docs,
                registry=registry,
            )

        @app.get("/documents")
        async def list_documents(
            docs: list[Document] = AuthzDep(Document, "read"),  # type: ignore[assignment]
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
        """Sync sessions continue to work (backward compat)."""
        # This is already tested by the existing tests; included for clarity
        response = client.get("/articles")
        assert response.status_code == 200
        assert len(response.json()) == 2

    def test_async_session_detected(
        self, seeded_session: Session, registry: PolicyRegistry
    ) -> None:
        """When an AsyncSession is provided, await is used for execute."""
        # We mock AsyncSession detection to verify the code path is exercised.
        # We can't easily set up a real async engine without aiosqlite,
        # so we verify via mocking that the async branch is taken.
        registry.register(
            Article,
            "read",
            lambda actor: Article.is_published == True,  # noqa: E712
            name="read_published",
            description="Viewers can read published articles",
        )

        # Create a mock AsyncSession
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [
            Article(id=1, title="Mocked", is_published=True, owner_id=1)
        ]

        mock_async_session = AsyncMock()
        mock_async_session.execute = AsyncMock(return_value=mock_result)

        app = FastAPI()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            configure_authz(
                app=app,
                get_actor=lambda r: Actor(id=1),
                get_session=lambda r: mock_async_session,
                registry=registry,
            )

        @app.get("/articles")
        async def list_articles(
            articles: list[Article] = AuthzDep(Article, "read"),  # type: ignore[assignment]
        ) -> list[dict]:
            return [{"id": a.id, "title": a.title} for a in articles]

        # Patch AsyncSession so isinstance check works
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

        # Verify await was used (execute was called as a coroutine)
        mock_async_session.execute.assert_awaited()


class TestDependencyInjection:
    """Sentinel dependency functions for DI-based configuration."""

    def test_get_actor_raises_not_implemented(self) -> None:
        """get_actor sentinel raises NotImplementedError when not overridden."""
        mock_request = MagicMock(spec=Request)
        # No app.state.sqla_authz_get_actor set
        mock_request.app.state = MagicMock(spec=[])
        with pytest.raises(NotImplementedError, match="Override get_actor"):
            get_actor(mock_request)

    def test_get_session_raises_not_implemented(self) -> None:
        """get_session sentinel raises NotImplementedError when not overridden."""
        mock_request = MagicMock(spec=Request)
        # No app.state.sqla_authz_get_session set
        mock_request.app.state = MagicMock(spec=[])
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

        # Use DI overrides — the documented pattern
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
        """When neither DI override nor configure_authz is used, NotImplementedError surfaces."""
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


class TestConfigureAuthzDeprecation:
    """configure_authz() emits DeprecationWarning."""

    def test_emits_deprecation_warning(self, seeded_session: Session) -> None:
        """configure_authz emits a DeprecationWarning."""
        app = FastAPI()
        with pytest.warns(DeprecationWarning, match="deprecated"):
            configure_authz(
                app=app,
                get_actor=lambda r: Actor(id=1),
                get_session=lambda r: seeded_session,
            )

    def test_still_stores_state_after_deprecation(self, seeded_session: Session) -> None:
        """configure_authz still works functionally despite deprecation."""
        app = FastAPI()

        def actor_fn(request):
            return Actor(id=1)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            configure_authz(
                app=app,
                get_actor=actor_fn,
                get_session=lambda r: seeded_session,
            )
        assert app.state.sqla_authz_get_actor is actor_fn
