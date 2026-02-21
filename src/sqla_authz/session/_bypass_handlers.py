"""Bypass event handlers for strict mode and audit logging."""

from __future__ import annotations

import logging
import warnings

from sqlalchemy.orm import ORMExecuteState

from sqla_authz.config._config import AuthzConfig
from sqla_authz.exceptions import AuthzBypassError
from sqla_authz.policy._registry import PolicyRegistry

__all__ = [
    "handle_column_load_bypass",
    "handle_no_entity_bypass",
    "handle_skip_authz_bypass",
]

logger = logging.getLogger("sqla_authz.bypass")


def handle_column_load_bypass(
    orm_execute_state: ORMExecuteState,
    config: AuthzConfig,
    registry: PolicyRegistry,
) -> None:
    """Handle session.get() / column load bypass.

    Called when the interceptor detects ``is_column_load`` or
    ``is_relationship_load`` on a SELECT.  Depending on
    ``config.on_unprotected_get``, this may warn, raise, or be silent.
    """
    # Try to extract entity from the mapper
    entity: type | None = None
    try:
        if hasattr(orm_execute_state, "bind_mapper") and orm_execute_state.bind_mapper is not None:
            entity = orm_execute_state.bind_mapper.class_
    except Exception:  # noqa: BLE001
        pass

    if entity is None or not registry.has_policy(entity, config.default_action):
        return  # No policy for this entity, nothing to warn about

    msg = (
        f"Unprotected column load for {entity.__name__} — "
        f"session.get() bypasses authorization. "
        f"Use safe_get() or can(actor, action, obj) for post-load checks."
    )

    if config.on_unprotected_get == "raise":
        raise AuthzBypassError(msg)
    elif config.on_unprotected_get == "warn":
        warnings.warn(msg, stacklevel=4)

    if config.audit_bypasses:
        logger.warning("BYPASS:column_load — %s", msg)


def handle_skip_authz_bypass(
    orm_execute_state: ORMExecuteState,
    config: AuthzConfig,
) -> None:
    """Handle skip_authz=True bypass.

    Called when the interceptor detects ``skip_authz=True`` in execution
    options.  Depending on ``config.on_skip_authz``, this may log, warn,
    or be silent.
    """
    msg = "skip_authz=True used — authorization bypassed"

    if config.on_skip_authz == "log":
        logger.info("BYPASS:skip_authz — %s", msg)
    elif config.on_skip_authz == "warn":
        warnings.warn(msg, stacklevel=4)

    if config.audit_bypasses:
        logger.warning("BYPASS:skip_authz — %s", msg)


def handle_no_entity_bypass(
    orm_execute_state: ORMExecuteState,
    config: AuthzConfig,
) -> None:
    """Handle text() or core query with no ORM entities.

    Called when the interceptor iterates over column descriptions and
    finds no ORM entities at all.  Depending on ``config.on_text_query``,
    this may raise, warn, or be silent.
    """
    msg = "Query has no ORM entities — authorization not applied (text() or core query)"

    if config.on_text_query == "raise":
        raise AuthzBypassError(msg)
    elif config.on_text_query == "warn":
        warnings.warn(msg, stacklevel=4)

    if config.audit_bypasses:
        logger.warning("BYPASS:no_entity — %s", msg)
