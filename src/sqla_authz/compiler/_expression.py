"""Policy evaluation — call policy functions and combine filter expressions."""

from __future__ import annotations

from functools import reduce

from sqlalchemy import ColumnElement, false

from sqla_authz._types import ActorLike
from sqla_authz.config._config import get_global_config
from sqla_authz.policy._registry import PolicyRegistry

__all__ = ["evaluate_policies"]


def evaluate_policies(
    registry: PolicyRegistry,
    resource_type: type,
    action: str,
    actor: ActorLike,
) -> ColumnElement[bool]:
    """Evaluate all registered policies for (resource_type, action).

    Multiple policies for the same key are combined with OR — any
    matching policy grants access.

    Returns ``false()`` (deny by default) when no policies are registered.

    When ``log_policy_decisions`` is enabled in the global config, logs
    policy evaluation at INFO/DEBUG/WARNING levels via the ``sqla_authz``
    logger.

    Args:
        registry: The policy registry to look up.
        resource_type: The SQLAlchemy model class.
        action: The action string.
        actor: The current actor/principal.

    Returns:
        A ``ColumnElement[bool]`` suitable for ``Select.where()``.
    """
    policies = registry.lookup(resource_type, action)

    if not policies:
        config = get_global_config()
        if config.log_policy_decisions:
            from sqla_authz._audit import log_policy_evaluation

            log_policy_evaluation(
                entity=resource_type,
                action=action,
                actor=actor,
                policies=policies,
                result_expr=false(),
            )
        return false()

    filters: list[ColumnElement[bool]] = [p.fn(actor) for p in policies]
    result = reduce(lambda a, b: a | b, filters)

    config = get_global_config()
    if config.log_policy_decisions:
        from sqla_authz._audit import log_policy_evaluation

        log_policy_evaluation(
            entity=resource_type,
            action=action,
            actor=actor,
            policies=policies,
            result_expr=result,
        )

    return result
