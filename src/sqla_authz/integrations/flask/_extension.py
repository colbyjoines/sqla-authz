"""Flask extension for sqla-authz authorization."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from flask import Flask, current_app, jsonify
from sqlalchemy import Select

from sqla_authz._types import ActorLike
from sqla_authz.compiler._query import authorize_query as _authorize_query
from sqla_authz.config._config import AuthzConfig
from sqla_authz.exceptions import AuthorizationDenied, NoPolicyError
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = ["AuthzExtension"]


class AuthzExtension:
    """Flask extension that provides authorization query filtering.

    Integrates sqla-authz with Flask by registering error handlers and
    providing an ``authorize_query()`` method that applies policies to
    SQLAlchemy SELECT statements within request context.

    Supports the Flask app-factory pattern via ``init_app()``.

    Args:
        app: Optional Flask application. If provided, calls ``init_app()``
            immediately.
        actor_provider: A callable ``() -> ActorLike`` that returns the
            current actor. Called within request context.
        default_action: Default action string when none is specified.
            Defaults to ``"read"``.
        registry: Optional policy registry. Defaults to the global registry.
        config: Optional authorization config. Defaults to the global config.

    Example::

        from flask import Flask
        from sqla_authz.integrations.flask import AuthzExtension

        app = Flask(__name__)
        authz = AuthzExtension(
            app,
            actor_provider=lambda: get_current_user(),
        )

        @app.get("/posts")
        def list_posts():
            stmt = select(Post)
            stmt = authz.authorize_query(stmt)
            return session.execute(stmt).scalars().all()
    """

    def __init__(
        self,
        app: Flask | None = None,
        *,
        actor_provider: Callable[[], ActorLike],
        default_action: str = "read",
        registry: PolicyRegistry | None = None,
        config: AuthzConfig | None = None,
    ) -> None:
        self._actor_provider = actor_provider
        self._default_action = default_action
        self._registry = registry
        self._config = config

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """Initialize the extension with a Flask application.

        Stores configuration on ``app.extensions["sqla_authz"]`` and
        registers error handlers for authorization exceptions.

        Args:
            app: The Flask application instance.

        Example::

            authz = AuthzExtension(
                actor_provider=lambda: get_current_user(),
            )
            app = Flask(__name__)
            authz.init_app(app)
        """
        app.extensions["sqla_authz"] = {
            "actor_provider": self._actor_provider,
            "default_action": self._default_action,
            "registry": self._registry,
            "config": self._config,
        }

        @app.errorhandler(AuthorizationDenied)
        def handle_authz_denied(exc: AuthorizationDenied):  # pyright: ignore[reportUnusedFunction]
            return jsonify({"detail": str(exc)}), 403

        @app.errorhandler(NoPolicyError)
        def handle_no_policy(exc: NoPolicyError):  # pyright: ignore[reportUnusedFunction]
            return jsonify({"detail": str(exc)}), 500

    def authorize_query(
        self,
        stmt: Select[Any],
        *,
        action: str | None = None,
    ) -> Select[Any]:
        """Apply authorization filters to a SQLAlchemy SELECT statement.

        Must be called within a Flask request context. Resolves the current
        actor via the configured ``actor_provider`` and delegates to the
        core ``authorize_query()`` compiler.

        Args:
            stmt: A SQLAlchemy 2.0 SELECT statement.
            action: The authorization action. Defaults to the extension's
                ``default_action``.

        Returns:
            A new SELECT with authorization filters applied.

        Example::

            @app.get("/posts")
            def list_posts():
                stmt = select(Post)
                stmt = authz.authorize_query(stmt, action="read")
                return session.execute(stmt).scalars().all()
        """
        ext_state: dict[str, Any] = current_app.extensions["sqla_authz"]

        actor_provider: Callable[[], ActorLike] = ext_state["actor_provider"]
        actor = actor_provider()

        effective_action = action if action is not None else ext_state["default_action"]

        registry: PolicyRegistry | None = ext_state["registry"]
        if registry is None:
            registry = get_default_registry()

        return _authorize_query(
            stmt,
            actor=actor,
            action=effective_action,
            registry=registry,
        )
