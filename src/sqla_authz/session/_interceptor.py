"""Session interceptor — do_orm_execute event hook for automatic authorization."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from sqlalchemy import Select, event
from sqlalchemy.orm import ORMExecuteState, Session, sessionmaker, with_loader_criteria

from sqla_authz._types import ActorLike
from sqla_authz.compiler._expression import evaluate_policies
from sqla_authz.config._config import AuthzConfig, get_global_config
from sqla_authz.exceptions import NoPolicyError
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

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
        # Only intercept SELECT statements
        if not orm_execute_state.is_select:
            return

        # Skip internal loads (column/relationship lazy loads)
        if orm_execute_state.is_column_load or orm_execute_state.is_relationship_load:
            return

        # Skip if explicitly opted out
        if orm_execute_state.execution_options.get("skip_authz", False):
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
