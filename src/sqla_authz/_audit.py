"""Audit logging for policy evaluation decisions."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from sqlalchemy import ColumnElement

from sqla_authz._types import ActorLike
from sqla_authz.policy._base import PolicyRegistration

__all__ = ["log_bypass_event", "log_policy_evaluation"]

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


def log_bypass_event(
    *,
    bypass_type: str,
    entity: type | None = None,
    statement_hint: str = "",
    detail: str = "",
) -> None:
    """Log a bypass event to a type-specific sub-logger.

    Each bypass type gets its own logger under ``sqla_authz.bypass.<type>``
    so operators can enable/disable granularly.

    Args:
        bypass_type: Category of bypass (e.g., ``"column_load"``,
            ``"skip_authz"``, ``"no_entity"``).
        entity: The model class involved, if known.
        statement_hint: A short hint about the statement (truncated to 200 chars).
        detail: Additional detail about the bypass event.
    """
    bypass_logger = logging.getLogger(f"sqla_authz.bypass.{bypass_type}")
    bypass_logger.warning(
        "BYPASS:%s entity=%s stmt=%s — %s",
        bypass_type,
        entity.__name__ if entity else "<unknown>",
        statement_hint[:200],
        detail,
    )
