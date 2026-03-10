"""Point checks for specific resource instances."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase, Session

from sqla_authz._action_validation import check_unknown_action
from sqla_authz._types import ActorLike
from sqla_authz.actions import CREATE
from sqla_authz.compiler._eval import eval_expression
from sqla_authz.compiler._expression import evaluate_policies
from sqla_authz.exceptions import AuthorizationDenied, QueryOnlyPolicyError
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = ["authorize", "authorize_create", "can", "can_create"]


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

    Raises:
        QueryOnlyPolicyError: If any matching policy is marked
            ``query_only=True``.

    Example::

        post = session.get(Post, 1)
        if can(current_user, "read", post):
            return post
    """
    target_registry = registry if registry is not None else get_default_registry()

    check_unknown_action(target_registry, action)

    resource_type = type(resource)

    # Check for query-only policies before attempting in-memory evaluation
    policies = target_registry.lookup(resource_type, action)
    if any(p.query_only for p in policies):
        raise QueryOnlyPolicyError(
            resource_type=resource_type.__name__,
            action=action,
            query_only_policies=[p.name for p in policies if p.query_only],
        )

    filter_expr = evaluate_policies(
        target_registry, resource_type, action, actor, policies=policies
    )

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
        QueryOnlyPolicyError: If any matching policy is marked
            ``query_only=True``.

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


def can_create(
    actor: ActorLike,
    resource: DeclarativeBase,
    *,
    registry: PolicyRegistry | None = None,
    session: Session | None = None,
) -> bool:
    """Check whether *actor* can create *resource* in its current state.

    This is a convenience wrapper around ``can(..., action="create")`` for
    pending or transient ORM instances. Populate the object first, then call
    ``can_create()`` before flushing or committing.

    Args:
        actor: The user/principal attempting the create.
        resource: The pending mapped SQLAlchemy model instance.
        registry: Optional custom registry. Defaults to the global registry.
        session: Optional session (reserved for future use).

    Returns:
        ``True`` if creation is allowed, ``False`` otherwise.
    """
    return can(actor, CREATE, resource, registry=registry, session=session)


def authorize_create(
    actor: ActorLike,
    resource: DeclarativeBase,
    *,
    registry: PolicyRegistry | None = None,
    message: str | None = None,
    session: Session | None = None,
) -> None:
    """Assert that *actor* can create *resource* in its current state.

    This is a convenience wrapper around ``authorize(..., action="create")``
    for pending or transient ORM instances.

    Args:
        actor: The user/principal attempting the create.
        resource: The pending mapped SQLAlchemy model instance.
        registry: Optional custom registry. Defaults to the global registry.
        message: Optional custom error message for the exception.
        session: Optional session (reserved for future use).
    """
    authorize(
        actor,
        CREATE,
        resource,
        registry=registry,
        message=message,
        session=session,
    )
