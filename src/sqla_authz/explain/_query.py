"""explain_query() — explain how authorization filters would be applied."""

from __future__ import annotations

from functools import reduce
from typing import Any

from sqlalchemy import ColumnElement, Select, false

from sqla_authz._types import ActorLike
from sqla_authz.explain._models import (
    AuthzExplanation,
    EntityExplanation,
    PolicyEvaluation,
)
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = ["explain_query"]


def _compile_sql(expr: ColumnElement[bool]) -> str:
    """Compile a SQLAlchemy expression to SQL with literal binds."""
    return str(expr.compile(compile_kwargs={"literal_binds": True}))


def explain_query(
    stmt: Select[Any],
    *,
    actor: ActorLike,
    action: str,
    registry: PolicyRegistry | None = None,
) -> AuthzExplanation:
    """Explain how authorization filters would be applied to a SELECT.

    Does not execute the query. Instead, returns a structured explanation
    of which policies would be applied, what SQL filters they produce,
    and what the final authorized query would look like.

    Args:
        stmt: A SQLAlchemy 2.0 Select statement.
        actor: The user/principal.
        action: The action string (e.g., ``"read"``).
        registry: Optional custom registry. Defaults to the global registry.

    Returns:
        An ``AuthzExplanation`` with per-entity breakdowns and the
        compiled authorized SQL.
    """
    target_registry = registry if registry is not None else get_default_registry()

    entities: list[EntityExplanation] = []
    authorized_stmt = stmt
    has_deny_by_default = False

    desc_list: list[dict[str, Any]] = stmt.column_descriptions
    for desc in desc_list:
        entity: type | None = desc.get("entity")
        if entity is None:
            continue

        policies = target_registry.lookup(entity, action)

        if not policies:
            # Deny by default
            has_deny_by_default = True
            combined_sql = _compile_sql(false())
            authorized_stmt = authorized_stmt.where(false())
            entities.append(
                EntityExplanation(
                    entity_name=entity.__name__,
                    entity_type=f"{entity.__module__}.{entity.__qualname__}",
                    action=action,
                    policies_found=0,
                    policies=[],
                    combined_filter_sql=combined_sql,
                    deny_by_default=True,
                )
            )
            continue

        # Evaluate each policy individually
        policy_evals: list[PolicyEvaluation] = []
        filter_exprs: list[ColumnElement[bool]] = []
        for p in policies:
            expr = p.fn(actor)
            filter_exprs.append(expr)
            policy_evals.append(
                PolicyEvaluation(
                    name=p.name,
                    description=p.description,
                    filter_expression=str(expr),
                    filter_sql=_compile_sql(expr),
                )
            )

        combined_expr = reduce(lambda a, b: a | b, filter_exprs)
        combined_sql = _compile_sql(combined_expr)
        authorized_stmt = authorized_stmt.where(combined_expr)

        entities.append(
            EntityExplanation(
                entity_name=entity.__name__,
                entity_type=f"{entity.__module__}.{entity.__qualname__}",
                action=action,
                policies_found=len(policies),
                policies=policy_evals,
                combined_filter_sql=combined_sql,
                deny_by_default=False,
            )
        )

    authorized_sql = str(authorized_stmt.compile(compile_kwargs={"literal_binds": True}))

    return AuthzExplanation(
        action=action,
        actor_repr=repr(actor),
        entities=entities,
        authorized_sql=authorized_sql,
        has_deny_by_default=has_deny_by_default,
    )
