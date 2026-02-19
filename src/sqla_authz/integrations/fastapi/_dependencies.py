"""FastAPI dependencies for sqla-authz authorization."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, Request
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from sqla_authz._types import ActorLike
from sqla_authz.compiler._query import authorize_query
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = ["AuthzDep", "configure_authz"]


def configure_authz(
    *,
    app: Any,
    get_actor: Callable[..., ActorLike],
    get_session: Callable[..., Session],
    registry: PolicyRegistry | None = None,
) -> None:
    """Configure global authorization providers for FastAPI integration.

    Stores the actor and session provider functions on the FastAPI app
    state, making them available to ``AuthzDep`` dependencies.

    Args:
        app: The FastAPI application instance.
        get_actor: A callable ``(request) -> ActorLike`` that resolves
            the current actor from the request.
        get_session: A callable ``(request) -> Session`` that resolves
            the current SQLAlchemy session from the request.
        registry: Optional policy registry. Defaults to the global registry.

    Example::

        from fastapi import FastAPI, Request
        from sqla_authz.integrations.fastapi import configure_authz

        app = FastAPI()

        configure_authz(
            app=app,
            get_actor=lambda request: get_current_user(request),
            get_session=lambda request: get_db(request),
        )
    """
    app.state.sqla_authz_get_actor = get_actor
    app.state.sqla_authz_get_session = get_session
    app.state.sqla_authz_registry = registry


def _make_dependency(
    model: type,
    action: str,
    *,
    id_param: str | None = None,
    registry: PolicyRegistry | None = None,
) -> Callable[..., Any]:
    """Build the async dependency function for a given model/action."""

    async def _resolve(request: Request) -> Any:
        app_state = request.app.state
        actor: ActorLike = app_state.sqla_authz_get_actor(request)
        session: Session = app_state.sqla_authz_get_session(request)

        effective_registry = registry
        if effective_registry is None:
            effective_registry = app_state.sqla_authz_registry
        if effective_registry is None:
            effective_registry = get_default_registry()

        stmt: Select[Any] = select(model)

        if id_param is not None:
            pk_value = request.path_params[id_param]
            pk_col: Any = getattr(model, "id")
            stmt = stmt.where(pk_col == pk_value)

        stmt = authorize_query(stmt, actor=actor, action=action, registry=effective_registry)

        result = session.execute(stmt).scalars().all()

        if id_param is not None:
            if not result:
                raise HTTPException(status_code=404, detail="Not found")
            return result[0]

        return list(result)

    return _resolve


def AuthzDep(
    model: type,
    action: str,
    *,
    id_param: str | None = None,
    registry: PolicyRegistry | None = None,
) -> Any:
    """FastAPI dependency for authorized queries.

    Returns a ``Depends()`` instance that resolves authorized model
    instances by applying registered policies. When ``id_param`` is
    ``None``, returns a list of all authorized instances (collection
    endpoint). When ``id_param`` is set, fetches a single instance by
    primary key from the named path parameter, returning 404 if not
    found or not authorized.

    Use directly as a default parameter value in route signatures.

    Args:
        model: The SQLAlchemy model class to query.
        action: The authorization action (e.g., ``"read"``).
        id_param: Path parameter name for single-item lookups.
        registry: Optional per-dependency registry override.

    Returns:
        A FastAPI ``Depends`` instance.

    Example::

        @app.get("/posts")
        async def list_posts(
            posts: list[Post] = AuthzDep(Post, "read"),
        ) -> list[dict]:
            return [{"id": p.id, "title": p.title} for p in posts]

        @app.get("/posts/{post_id}")
        async def get_post(
            post: Post = AuthzDep(Post, "read", id_param="post_id"),
        ) -> dict:
            return {"id": post.id, "title": post.title}
    """
    dep_fn = _make_dependency(model, action, id_param=id_param, registry=registry)
    return Depends(dep_fn)
