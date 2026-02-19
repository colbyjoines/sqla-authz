"""Audit logging for policy evaluation decisions."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from sqlalchemy import ColumnElement

from sqla_authz._types import ActorLike
from sqla_authz.policy._base import PolicyRegistration

__all__ = ["log_policy_evaluation"]

logger = logging.getLogger("sqla_authz")


def log_policy_evaluation(
    *,
    entity: type,
    action: str,
    actor: ActorLike,
    policies: Sequence[PolicyRegistration],
    result_expr: ColumnElement[bool],
) -> None:
    """Log a policy evaluation decision.

    Logging levels:
    - INFO: Summary (entity, action, policy count)
    - DEBUG: Detailed (which policies matched, filter expression)
    - WARNING: No policy found (deny-by-default triggered)

    Example::

        log_policy_evaluation(
            entity=Post,
            action="read",
            actor=current_user,
            policies=matched_policies,
            result_expr=compiled_filter,
        )
    """
    entity_name = entity.__name__
    policy_count = len(policies)

    if policy_count == 0:
        logger.warning(
            "No policy registered for (%s, %r) — deny-by-default applied",
            entity_name,
            action,
        )
        return

    # INFO: summary
    logger.info(
        "Policy evaluation: %s.%s — %d policy(ies) applied for actor %r",
        entity_name,
        action,
        policy_count,
        actor,
    )

    # DEBUG: details
    if logger.isEnabledFor(logging.DEBUG):
        policy_names = [p.name for p in policies]
        logger.debug(
            "Policies matched for %s.%s: %s — filter: %s",
            entity_name,
            action,
            policy_names,
            result_expr,
        )
