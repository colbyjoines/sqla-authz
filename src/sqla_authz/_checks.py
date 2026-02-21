"""Point checks — can() and authorize() for single resource instances."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase, Session

from sqla_authz._types import ActorLike
from sqla_authz.compiler._eval import eval_expression
from sqla_authz.compiler._expression import evaluate_policies
from sqla_authz.exceptions import AuthorizationDenied
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = ["can", "authorize"]


def can(
    actor: ActorLike,
    action: str,
    resource: DeclarativeBase,
    *,
    registry: PolicyRegistry | None = None,
    session: Session | None = None,
) -> bool:
    """Check if *actor* can perform *action* on a specific resource instance.

    Returns ``True`` if the policy filter matches the resource, ``False``
    otherwise.  The real application database is **never** touched — the
    filter expression is evaluated in-memory by walking the SQLAlchemy
    ColumnElement AST.

    Args:
        actor: The user/principal performing the action.
        action: The action string (e.g., ``"read"``, ``"update"``).
        resource: A mapped SQLAlchemy model instance.
        registry: Optional custom registry.  Defaults to the global registry.
        session: Optional session (reserved for future use).

    Returns:
        ``True`` if access is granted, ``False`` if denied.

    Example::

        post = session.get(Post, 1)
        if can(current_user, "read", post):
            return post
    """
    target_registry = registry if registry is not None else get_default_registry()
    resource_type = type(resource)

    filter_expr = evaluate_policies(target_registry, resource_type, action, actor)

    return eval_expression(filter_expr, resource)


def authorize(
    actor: ActorLike,
    action: str,
    resource: DeclarativeBase,
    *,
    registry: PolicyRegistry | None = None,
    message: str | None = None,
    session: Session | None = None,
) -> None:
    """Assert that *actor* is authorized to perform *action* on *resource*.

    Raises :class:`~sqla_authz.exceptions.AuthorizationDenied` when access
    is denied.  Returns ``None`` on success.

    Args:
        actor: The user/principal performing the action.
        action: The action string (e.g., ``"read"``, ``"update"``).
        resource: A mapped SQLAlchemy model instance.
        registry: Optional custom registry.  Defaults to the global registry.
        message: Optional custom error message for the exception.
        session: Optional session (reserved for future use).

    Raises:
        AuthorizationDenied: If the actor is not authorized.

    Example::

        authorize(current_user, "update", post)  # raises if denied
    """
    if not can(actor, action, resource, registry=registry, session=session):
        raise AuthorizationDenied(
            actor=actor,
            action=action,
            resource_type=type(resource).__name__,
            message=message,
        )
