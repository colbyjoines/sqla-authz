"""Safe alternatives to session.get() that include authorization checks."""

from __future__ import annotations

from typing import Any, TypeVar

from sqlalchemy.orm import DeclarativeBase, Session

from sqla_authz._checks import can
from sqla_authz._types import ActorLike
from sqla_authz.exceptions import AuthorizationDenied
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = ["safe_get", "safe_get_or_raise"]

T = TypeVar("T", bound=DeclarativeBase)


def safe_get(
    session: Session,
    entity_class: type[T],
    pk: Any,
    *,
    actor: ActorLike,
    action: str = "read",
    registry: PolicyRegistry | None = None,
) -> T | None:
    """Load an entity by primary key and check authorization.

    Returns the entity if found and authorized, ``None`` if the entity
    does not exist **or** if the actor is not authorized to access it.

    Args:
        session: The SQLAlchemy session to load from.
        entity_class: The mapped model class to load.
        pk: The primary key value.
        actor: The actor performing the action.
        action: The action to check (default ``"read"``).
        registry: Optional custom policy registry.

    Returns:
        The entity instance if found and authorized, ``None`` otherwise.

    Example::

        post = safe_get(session, Post, 42, actor=current_user)
        if post is None:
            raise HTTPException(404)
    """
    obj = session.get(entity_class, pk)
    if obj is None:
        return None
    target_registry = registry if registry is not None else get_default_registry()
    if not can(actor, action, obj, registry=target_registry):
        return None
    return obj


def safe_get_or_raise(
    session: Session,
    entity_class: type[T],
    pk: Any,
    *,
    actor: ActorLike,
    action: str = "read",
    registry: PolicyRegistry | None = None,
    message: str | None = None,
) -> T | None:
    """Load an entity by primary key and assert authorization.

    Returns the entity if found and authorized, ``None`` if the entity
    does not exist.  Raises :class:`~sqla_authz.exceptions.AuthorizationDenied`
    if the entity exists but the actor is not authorized.

    Args:
        session: The SQLAlchemy session to load from.
        entity_class: The mapped model class to load.
        pk: The primary key value.
        actor: The actor performing the action.
        action: The action to check (default ``"read"``).
        registry: Optional custom policy registry.
        message: Optional custom error message for the exception.

    Returns:
        The entity instance if found and authorized, ``None`` if not found.

    Raises:
        AuthorizationDenied: If the entity exists but the actor is denied.

    Example::

        post = safe_get_or_raise(session, Post, 42, actor=current_user)
        if post is None:
            raise HTTPException(404)
    """
    obj = session.get(entity_class, pk)
    if obj is None:
        return None
    target_registry = registry if registry is not None else get_default_registry()
    if not can(actor, action, obj, registry=target_registry):
        raise AuthorizationDenied(
            actor=actor,
            action=action,
            resource_type=entity_class.__name__,
            message=message,
        )
    return obj
