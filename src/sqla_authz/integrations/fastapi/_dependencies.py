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

__all__ = ["AuthzDep", "get_actor", "get_session"]


# ---------------------------------------------------------------------------
# Sentinel dependency functions for DI-based configuration
# ---------------------------------------------------------------------------


def get_actor(request: Request) -> ActorLike:
    """Sentinel dependency — override via ``app.dependency_overrides[get_actor]``.

    Raises ``NotImplementedError`` when called directly. Override this
    dependency in your FastAPI app to provide the current actor.

    Example::

        from sqla_authz.integrations.fastapi import get_actor

        app.dependency_overrides[get_actor] = my_get_current_user
    """
    raise NotImplementedError(
        "Override get_actor via app.dependency_overrides[get_actor]. "
        "See sqla-authz docs for configuration guide."
    )


def get_session(request: Request) -> Session:
    """Sentinel dependency — override via ``app.dependency_overrides[get_session]``.

    Raises ``NotImplementedError`` when called directly. Override this
    dependency in your FastAPI app to provide the current SQLAlchemy session.

    Example::

        from sqla_authz.integrations.fastapi import get_session

        app.dependency_overrides[get_session] = my_get_db_session
    """
    raise NotImplementedError(
        "Override get_session via app.dependency_overrides[get_session]. "
        "See sqla-authz docs for configuration guide."
    )


# ---------------------------------------------------------------------------
# Async session detection helper
# ---------------------------------------------------------------------------


def _is_async_session(session: object) -> bool:
    """Check if a session is an AsyncSession without hard-importing asyncio extras."""
    try:
        from sqlalchemy.ext.asyncio import AsyncSession

        return isinstance(session, AsyncSession)
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Dependency builder
# ---------------------------------------------------------------------------


def _make_dependency(
    model: type,
    action: str,
    *,
    id_param: str | None = None,
    pk_column: str = "id",
    registry: PolicyRegistry | None = None,
) -> Callable[..., Any]:
    """Build the async dependency function for a given model/action.

    Args:
        model: The SQLAlchemy model class to query.
        action: The authorization action string.
        id_param: Path parameter name for single-item lookups.
        pk_column: Model attribute name for the primary key column.
        registry: Optional per-dependency registry override.
    """
    # Import module-level sentinels for Depends references
    from sqla_authz.integrations.fastapi._dependencies import (  # noqa: I001
        get_actor as _get_actor,
        get_session as _get_session,
    )

    async def _resolve(
        request: Request,
        actor: ActorLike = Depends(_get_actor),
        session: Session = Depends(_get_session),
    ) -> Any:
        effective_registry = registry if registry is not None else get_default_registry()

        stmt: Select[Any] = select(model)

        if id_param is not None:
            pk_value = request.path_params[id_param]
            pk_col: Any = getattr(model, pk_column)
            stmt = stmt.where(pk_col == pk_value)

        stmt = authorize_query(stmt, actor=actor, action=action, registry=effective_registry)

        # Support both sync and async sessions
        if _is_async_session(session):
            result = (await session.execute(stmt)).scalars().all()  # type: ignore[union-attr]
        else:
            result = session.execute(stmt).scalars().all()

        if id_param is not None:
            if not result:
                raise HTTPException(status_code=404, detail="Not found")
            return result[0]  # pyright: ignore[reportUnknownVariableType]  # SA stubs

        return list(result)  # pyright: ignore[reportUnknownArgumentType]  # SA stubs

    return _resolve


def AuthzDep(
    model: type,
    action: str,
    *,
    id_param: str | None = None,
    pk_column: str = "id",
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
        pk_column: Model attribute name for the primary key column.
            Defaults to ``"id"``. Use this when your model's PK
            attribute has a different name (e.g., ``"uuid"``).
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

        # Model with non-'id' PK:
        @app.get("/documents/{doc_uuid}")
        async def get_document(
            doc: Document = AuthzDep(
                Document, "read", id_param="doc_uuid", pk_column="uuid"
            ),
        ) -> dict:
            return {"uuid": doc.uuid}
    """
    dep_fn = _make_dependency(
        model, action, id_param=id_param, pk_column=pk_column, registry=registry
    )
    return Depends(dep_fn)
