"""Point checks — can() and authorize() for single resource instances."""

from __future__ import annotations

from sqlalchemy import create_engine, literal_column, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import DeclarativeBase

from sqla_authz._types import ActorLike
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
) -> bool:
    """Check if *actor* can perform *action* on a specific resource instance.

    Returns ``True`` if the policy filter matches the resource, ``False``
    otherwise.  The real application database is **never** touched — the
    filter expression is evaluated against a temporary in-memory SQLite
    database containing only the single resource row.

    Args:
        actor: The user/principal performing the action.
        action: The action string (e.g., ``"read"``, ``"update"``).
        resource: A mapped SQLAlchemy model instance.
        registry: Optional custom registry.  Defaults to the global registry.

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

    # Evaluate the filter against the instance using a temporary in-memory
    # SQLite database.  This avoids any network I/O or touching the real DB.
    engine = create_engine("sqlite:///:memory:")
    resource_type.metadata.create_all(engine)

    mapper = sa_inspect(resource_type)
    table = mapper.local_table

    # Extract column values from the instance
    instance_state = sa_inspect(resource)
    col_values: dict[str, object] = {}
    for prop in mapper.column_attrs:
        col = prop.columns[0]
        col_values[col.key] = instance_state.attrs[prop.key].loaded_value

    with engine.connect() as conn:
        conn.execute(table.insert().values(**col_values))  # type: ignore[union-attr]
        stmt = select(literal_column("1")).select_from(table).where(filter_expr)  # type: ignore[union-attr]
        row = conn.execute(stmt).first()  # type: ignore[arg-type]
        conn.rollback()

    engine.dispose()
    return row is not None


def authorize(
    actor: ActorLike,
    action: str,
    resource: DeclarativeBase,
    *,
    registry: PolicyRegistry | None = None,
    message: str | None = None,
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

    Raises:
        AuthorizationDenied: If the actor is not authorized.

    Example::

        authorize(current_user, "update", post)  # raises if denied
    """
    if not can(actor, action, resource, registry=registry):
        raise AuthorizationDenied(
            actor=actor,
            action=action,
            resource_type=type(resource).__name__,
            message=message,
        )
