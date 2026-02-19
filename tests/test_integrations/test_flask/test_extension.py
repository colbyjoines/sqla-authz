"""Tests for Flask extension (AuthzExtension)."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import patch

import pytest
from flask import Flask
from sqlalchemy import Boolean, Integer, String, create_engine, select
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)

from sqla_authz.exceptions import AuthorizationDenied, NoPolicyError
from sqla_authz.integrations.flask._extension import AuthzExtension
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
def app_with_policies(seeded_session: Session, registry: PolicyRegistry) -> Flask:
    """Build a Flask app with policies and routes for testing."""
    registry.register(
        Article,
        "read",
        lambda actor: Article.is_published == True,  # noqa: E712
        name="read_published",
        description="Viewers can read published articles",
    )

    app = Flask(__name__)
    app.config["TESTING"] = True

    _current_actor = Actor(id=1, role="viewer")

    ext = AuthzExtension(
        app,
        actor_provider=lambda: _current_actor,
        default_action="read",
        registry=registry,
    )

    @app.get("/articles")
    def list_articles():
        stmt = select(Article)
        stmt = ext.authorize_query(stmt)
        rows = seeded_session.execute(stmt).scalars().all()
        return [{"id": a.id, "title": a.title} for a in rows]

    @app.get("/articles/<int:article_id>")
    def get_article(article_id: int):
        stmt = select(Article).where(Article.id == article_id)
        stmt = ext.authorize_query(stmt)
        row = seeded_session.execute(stmt).scalars().first()
        if row is None:
            return {"detail": "Not found"}, 404
        return {"id": row.id, "title": row.title}

    return app


@pytest.fixture()
def client(app_with_policies: Flask):
    return app_with_policies.test_client()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestExtensionInit:
    def test_init_registers_extension(self, registry: PolicyRegistry) -> None:
        """Extension is stored on app.extensions."""
        app = Flask(__name__)
        AuthzExtension(
            app,
            actor_provider=lambda: Actor(id=1),
            registry=registry,
        )
        assert "sqla_authz" in app.extensions

    def test_init_app_factory_pattern(self, registry: PolicyRegistry) -> None:
        """Extension works with init_app (app factory pattern)."""
        ext = AuthzExtension(
            actor_provider=lambda: Actor(id=1),
            registry=registry,
        )
        app = Flask(__name__)
        ext.init_app(app)
        assert "sqla_authz" in app.extensions

    def test_default_action(self, registry: PolicyRegistry) -> None:
        """Default action defaults to 'read'."""
        app = Flask(__name__)
        AuthzExtension(
            app,
            actor_provider=lambda: Actor(id=1),
            registry=registry,
        )
        with app.app_context():
            assert app.extensions["sqla_authz"]["default_action"] == "read"

    def test_custom_default_action(self, registry: PolicyRegistry) -> None:
        """Default action can be overridden."""
        app = Flask(__name__)
        AuthzExtension(
            app,
            actor_provider=lambda: Actor(id=1),
            default_action="list",
            registry=registry,
        )
        with app.app_context():
            assert app.extensions["sqla_authz"]["default_action"] == "list"


class TestAuthorizeQuery:
    def test_returns_authorized_results(self, client) -> None:
        """Collection endpoint returns only authorized (published) articles."""
        response = client.get("/articles")
        assert response.status_code == 200
        data = response.get_json()
        assert len(data) == 2
        titles = {d["title"] for d in data}
        assert "Published 1" in titles
        assert "Published 2" in titles
        assert "Draft" not in titles

    def test_single_item_authorized(self, client) -> None:
        """Authorized single item is returned."""
        response = client.get("/articles/1")
        assert response.status_code == 200
        data = response.get_json()
        assert data["id"] == 1
        assert data["title"] == "Published 1"

    def test_single_item_not_authorized(self, client) -> None:
        """Unauthorized item returns 404."""
        response = client.get("/articles/2")
        assert response.status_code == 404

    def test_single_item_not_found(self, client) -> None:
        """Non-existent item returns 404."""
        response = client.get("/articles/999")
        assert response.status_code == 404

    def test_custom_action_override(
        self, seeded_session: Session, registry: PolicyRegistry
    ) -> None:
        """authorize_query accepts an action override."""
        registry.register(
            Article,
            "edit",
            lambda actor: Article.owner_id == actor.id,
            name="edit_own",
            description="Edit own articles",
        )

        app = Flask(__name__)
        app.config["TESTING"] = True
        actor = Actor(id=1, role="editor")

        ext = AuthzExtension(
            app,
            actor_provider=lambda: actor,
            default_action="read",
            registry=registry,
        )

        @app.get("/editable")
        def list_editable():
            stmt = select(Article)
            stmt = ext.authorize_query(stmt, action="edit")
            rows = seeded_session.execute(stmt).scalars().all()
            return [{"id": a.id, "title": a.title} for a in rows]

        with app.test_client() as c:
            response = c.get("/editable")
            assert response.status_code == 200
            data = response.get_json()
            # owner_id=1 owns articles 1 and 2
            assert len(data) == 2
            ids = {d["id"] for d in data}
            assert ids == {1, 2}

    def test_deny_by_default_no_policy(self, seeded_session: Session) -> None:
        """With no policies registered, deny-by-default returns empty list."""
        empty_registry = PolicyRegistry()
        app = Flask(__name__)
        app.config["TESTING"] = True

        ext = AuthzExtension(
            app,
            actor_provider=lambda: Actor(id=1),
            registry=empty_registry,
        )

        @app.get("/articles")
        def list_articles():
            stmt = select(Article)
            stmt = ext.authorize_query(stmt)
            rows = seeded_session.execute(stmt).scalars().all()
            return [{"id": a.id, "title": a.title} for a in rows]

        with app.test_client() as c:
            response = c.get("/articles")
            assert response.status_code == 200
            assert response.get_json() == []


class TestErrorHandlers:
    def test_authorization_denied_returns_403(self, registry: PolicyRegistry) -> None:
        """AuthorizationDenied exception returns 403 JSON response."""
        app = Flask(__name__)
        app.config["TESTING"] = True

        AuthzExtension(
            app,
            actor_provider=lambda: Actor(id=1),
            registry=registry,
        )

        @app.get("/denied")
        def denied_route():
            raise AuthorizationDenied(
                actor=Actor(id=1),
                action="delete",
                resource_type="Article",
            )

        with app.test_client() as c:
            response = c.get("/denied")
            assert response.status_code == 403
            data = response.get_json()
            assert "detail" in data
            assert "not authorized" in data["detail"].lower()

    def test_no_policy_error_returns_500(self, registry: PolicyRegistry) -> None:
        """NoPolicyError exception returns 500 JSON response."""
        app = Flask(__name__)
        app.config["TESTING"] = True

        AuthzExtension(
            app,
            actor_provider=lambda: Actor(id=1),
            registry=registry,
        )

        @app.get("/no-policy")
        def no_policy_route():
            raise NoPolicyError(
                resource_type="Article",
                action="delete",
            )

        with app.test_client() as c:
            response = c.get("/no-policy")
            assert response.status_code == 500
            data = response.get_json()
            assert "detail" in data


class TestImportGuard:
    def test_import_guard_raises_helpful_error(self) -> None:
        """Import guard raises helpful ImportError when flask not installed."""
        import importlib

        import sqla_authz.integrations.flask as flask_mod

        with patch.dict("sys.modules", {"flask": None}):
            with pytest.raises(ImportError, match="Flask integration requires flask"):
                importlib.reload(flask_mod)
