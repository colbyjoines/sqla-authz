"""authorize_query() — apply authorization filters to SELECT statements."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Select

from sqla_authz._types import ActorLike
from sqla_authz.compiler._expression import evaluate_policies
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = ["authorize_query"]


def authorize_query(
    stmt: Select[Any],
    *,
    actor: ActorLike,
    action: str,
    registry: PolicyRegistry | None = None,
) -> Select[Any]:
    """Apply authorization filters to a SQLAlchemy SELECT statement.

    Looks up registered policies for the statement's entities and the
    given action, evaluates them with the actor, and applies the
    resulting WHERE clauses.

    Args:
        stmt: A SQLAlchemy 2.0 Select statement.
        actor: The user/principal. Must satisfy ActorLike protocol.
        action: The action being performed (e.g., "read", "update").
        registry: Optional custom registry. Defaults to the global registry.

    Returns:
        A new Select with authorization filters applied.

    Example::

        stmt = select(Post).where(Post.category == "tech")
        stmt = authorize_query(stmt, actor=current_user, action="read")
        # SQL: SELECT ... WHERE category = 'tech'
        #      AND (is_published OR author_id = :id)
    """
    target_registry = registry if registry is not None else get_default_registry()

    desc_list: list[dict[str, Any]] = stmt.column_descriptions
    for desc in desc_list:
        entity: type | None = desc.get("entity")
        if entity is None:
            continue

        filter_expr = evaluate_policies(target_registry, entity, action, actor)
        stmt = stmt.where(filter_expr)

    return stmt
