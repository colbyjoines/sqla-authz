"""Session interceptor — do_orm_execute event hook for automatic authorization."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from sqlalchemy import Delete, Select, Update, event
from sqlalchemy.orm import ORMExecuteState, Session, sessionmaker, with_loader_criteria
from sqlalchemy.sql.elements import TextClause

from sqla_authz._types import ActorLike
from sqla_authz.compiler._expression import evaluate_policies
from sqla_authz.config._config import AuthzConfig, get_global_config
from sqla_authz.exceptions import NoPolicyError, WriteDeniedError
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry
from sqla_authz.session._bypass_handlers import (
    handle_column_load_bypass,
    handle_no_entity_bypass,
    handle_skip_authz_bypass,
)

__all__ = ["install_interceptor", "authorized_sessionmaker"]


def _build_authz_handler(
    *,
    actor_provider: Callable[[], ActorLike],
    action: str,
    target_registry: PolicyRegistry,
    target_config: AuthzConfig,
) -> Callable[[ORMExecuteState], None]:
    """Build the do_orm_execute event handler function.

    Separated from ``install_interceptor`` to satisfy strict type checkers
    that flag nested event-handler functions as unused.
    """

    def _apply_authz(orm_execute_state: ORMExecuteState) -> None:
        # Only intercept SELECT statements (and optionally UPDATE/DELETE).
        # However, text() queries report is_select=False even when they
        # are SELECT statements.  Detect and handle them.
        if not orm_execute_state.is_select:
            # Check for write interception (UPDATE/DELETE)
            if _should_intercept_write(orm_execute_state, target_config):
                _apply_write_authz(
                    orm_execute_state,
                    actor_provider=actor_provider,
                    action=action,
                    target_registry=target_registry,
                    target_config=target_config,
                )
                return
            if isinstance(orm_execute_state.statement, TextClause):
                handle_no_entity_bypass(orm_execute_state, target_config)
            return

        # Skip internal loads (column/relationship lazy loads)
        if orm_execute_state.is_column_load or orm_execute_state.is_relationship_load:
            handle_column_load_bypass(orm_execute_state, target_config, target_registry)
            return

        # Skip if explicitly opted out
        if orm_execute_state.execution_options.get("skip_authz", False):
            handle_skip_authz_bypass(orm_execute_state, target_config)
            return

        actor = actor_provider()
        action_val: str = orm_execute_state.execution_options.get("authz_action", action)

        stmt = cast("Select[Any]", orm_execute_state.statement)
        desc_list: list[dict[str, Any]] = stmt.column_descriptions

        queried_entities: set[type] = set()
        for desc in desc_list:
            entity: type | None = desc.get("entity")
            if entity is None:
                continue

            queried_entities.add(entity)

            # Check on_missing_policy config
            if not target_registry.has_policy(entity, action_val):
                if target_config.on_missing_policy == "raise":
                    raise NoPolicyError(resource_type=entity.__name__, action=action_val)

            filter_expr = evaluate_policies(target_registry, entity, action_val, actor)
            stmt = stmt.where(filter_expr)
            stmt = stmt.options(with_loader_criteria(entity, filter_expr, include_aliases=True))

        # If no ORM entities were found, fire the no-entity bypass handler
        if not queried_entities:
            handle_no_entity_bypass(orm_execute_state, target_config)

        # Apply loader criteria for entities not in the main query but
        # that have registered policies — ensures relationship loads
        # (selectinload, lazy, joinedload) are also filtered.
        for reg_entity in target_registry.registered_entities(action_val):
            if reg_entity not in queried_entities:
                loader_expr = evaluate_policies(target_registry, reg_entity, action_val, actor)
                stmt = stmt.options(
                    with_loader_criteria(reg_entity, loader_expr, include_aliases=True)
                )

        orm_execute_state.statement = stmt

    return _apply_authz


def _should_intercept_write(
    orm_execute_state: ORMExecuteState,
    config: AuthzConfig,
) -> bool:
    """Return True if the statement is an UPDATE/DELETE that should be intercepted."""
    if orm_execute_state.is_update and config.intercept_updates:
        return True
    if orm_execute_state.is_delete and config.intercept_deletes:
        return True
    return False


def _apply_write_authz(
    orm_execute_state: ORMExecuteState,
    *,
    actor_provider: Callable[[], ActorLike],
    action: str,
    target_registry: PolicyRegistry,
    target_config: AuthzConfig,
) -> None:
    """Apply authorization filters to UPDATE/DELETE statements.

    When ``on_write_denied="raise"`` and no policy is registered for the
    entity+action, raises ``WriteDeniedError`` instead of silently adding
    ``WHERE FALSE``.

    When ``on_write_denied="filter"``, adds the policy filter as a WHERE
    clause so only authorized rows are affected.
    """
    # Skip if explicitly opted out
    if orm_execute_state.execution_options.get("skip_authz", False):
        handle_skip_authz_bypass(orm_execute_state, target_config)
        return

    actor = actor_provider()
    stmt = orm_execute_state.statement

    # Determine the action: use authz_action override, or derive from statement type
    if orm_execute_state.is_update:
        write_action: str = orm_execute_state.execution_options.get("authz_action", "update")
    else:
        write_action = orm_execute_state.execution_options.get("authz_action", "delete")

    # Extract entity from the statement's entity_description
    entity_desc: dict[str, Any] | None = getattr(stmt, "entity_description", None)
    if entity_desc is None:
        return

    entity: type | None = entity_desc.get("entity")
    if entity is None:
        return

    # Check on_write_denied behavior when no policy exists
    if not target_registry.has_policy(entity, write_action):
        if target_config.on_write_denied == "raise":
            raise WriteDeniedError(
                actor=actor,
                action=write_action,
                resource_type=entity.__name__,
            )
        # "filter" mode: proceed to add WHERE FALSE via evaluate_policies

    filter_expr = evaluate_policies(target_registry, entity, write_action, actor)
    write_stmt = cast("Update[Any] | Delete", stmt)
    orm_execute_state.statement = write_stmt.where(filter_expr)


def install_interceptor(
    session_factory: sessionmaker[Session],
    *,
    actor_provider: Callable[[], ActorLike],
    action: str = "read",
    registry: PolicyRegistry | None = None,
    config: AuthzConfig | None = None,
) -> None:
    """Install a ``do_orm_execute`` event listener on a session factory.

    The listener intercepts SELECT queries and applies authorization
    filters based on registered policies.

    Args:
        session_factory: A SQLAlchemy ``sessionmaker`` instance.
        actor_provider: A callable returning the current actor.
            Called once per query execution.
        action: Default action string. Can be overridden per-query
            via ``execution_options(authz_action="...")``.
        registry: Policy registry to use. Defaults to the global registry.
        config: Configuration to use. Defaults to the global config.

    Example::

        factory = sessionmaker(bind=engine)
        install_interceptor(
            factory,
            actor_provider=get_current_user,
            action="read",
        )

        with factory() as session:
            # All SELECT queries are automatically authorized
            posts = session.execute(select(Post)).scalars().all()
    """
    target_registry = registry if registry is not None else get_default_registry()
    target_config = config if config is not None else get_global_config()

    handler = _build_authz_handler(
        actor_provider=actor_provider,
        action=action,
        target_registry=target_registry,
        target_config=target_config,
    )
    event.listen(session_factory, "do_orm_execute", handler)


def authorized_sessionmaker(
    bind: Any,
    *,
    actor_provider: Callable[[], ActorLike],
    action: str = "read",
    registry: PolicyRegistry | None = None,
    config: AuthzConfig | None = None,
    **kwargs: Any,
) -> sessionmaker[Session]:
    """Create a sessionmaker with automatic authorization interception.

    Convenience factory that creates a ``sessionmaker`` and installs
    the authorization interceptor in one step.

    Args:
        bind: The engine or connection to bind to.
        actor_provider: A callable returning the current actor.
        action: Default action string.
        registry: Policy registry. Defaults to the global registry.
        config: Configuration. Defaults to the global config.
        **kwargs: Additional keyword arguments passed to ``sessionmaker``.

    Returns:
        A configured ``sessionmaker`` with authorization interception.

    Example::

        AuthorizedSession = authorized_sessionmaker(
            bind=engine,
            actor_provider=get_current_user,
            action="read",
        )

        with AuthorizedSession() as session:
            posts = session.execute(select(Post)).scalars().all()
            # Only authorized posts are returned
    """
    factory: sessionmaker[Session] = sessionmaker(bind=bind, **kwargs)
    install_interceptor(
        factory,
        actor_provider=actor_provider,
        action=action,
        registry=registry,
        config=config,
    )
    return factory
