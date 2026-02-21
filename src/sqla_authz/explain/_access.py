"""explain_access() — explain why an actor can/can't perform an action."""

from __future__ import annotations

from sqlalchemy import create_engine, literal_column, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import DeclarativeBase

from sqla_authz._types import ActorLike
from sqla_authz.explain._models import AccessExplanation, AccessPolicyEvaluation
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = ["explain_access"]


def _compile_sql(expr: object) -> str:
    """Compile a SQLAlchemy expression to SQL with literal binds."""
    return str(expr.compile(compile_kwargs={"literal_binds": True}))  # type: ignore[union-attr]


def explain_access(
    actor: ActorLike,
    action: str,
    resource: DeclarativeBase,
    *,
    registry: PolicyRegistry | None = None,
) -> AccessExplanation:
    """Explain why an actor can or cannot perform an action on a resource.

    Evaluates each policy individually against the resource instance
    using a temporary in-memory SQLite database (same approach as
    :func:`~sqla_authz.can`), and reports which policies matched.

    Args:
        actor: The user/principal performing the action.
        action: The action string (e.g., ``"read"``, ``"update"``).
        resource: A mapped SQLAlchemy model instance.
        registry: Optional custom registry. Defaults to the global registry.

    Returns:
        An ``AccessExplanation`` with per-policy match results and
        the overall allowed/denied verdict.
    """
    target_registry = registry if registry is not None else get_default_registry()
    resource_type = type(resource)
    policies = target_registry.lookup(resource_type, action)

    if not policies:
        return AccessExplanation(
            actor_repr=repr(actor),
            action=action,
            resource_type=resource_type.__name__,
            resource_repr=repr(resource),
            allowed=False,
            deny_by_default=True,
            policies=[],
        )

    # Set up temporary in-memory SQLite (same pattern as can())
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

    policy_evals: list[AccessPolicyEvaluation] = []
    any_matched = False

    with engine.connect() as conn:
        conn.execute(table.insert().values(**col_values))  # type: ignore[union-attr]

        for p in policies:
            expr = p.fn(actor)
            filter_sql = _compile_sql(expr)

            # Check if this individual policy matches the resource
            check_stmt = select(literal_column("1")).select_from(table).where(expr)  # type: ignore[union-attr]
            row = conn.execute(check_stmt).first()  # type: ignore[arg-type]
            matched = row is not None

            if matched:
                any_matched = True

            policy_evals.append(
                AccessPolicyEvaluation(
                    name=p.name,
                    description=p.description,
                    filter_sql=filter_sql,
                    matched=matched,
                )
            )

        conn.rollback()

    engine.dispose()

    return AccessExplanation(
        actor_repr=repr(actor),
        action=action,
        resource_type=resource_type.__name__,
        resource_repr=repr(resource),
        allowed=any_matched,
        deny_by_default=False,
        policies=policy_evals,
    )
