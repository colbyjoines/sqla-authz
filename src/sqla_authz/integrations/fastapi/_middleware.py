"""Middleware for automatic authorization via session interceptor."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqla_authz._types import ActorLike
from sqla_authz.config._config import AuthzConfig
from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.session._interceptor import install_interceptor

__all__ = ["install_authz_interceptor"]


def install_authz_interceptor(
    session_factory: Any,
    *,
    actor_provider: Callable[[], ActorLike],
    action: str = "read",
    registry: PolicyRegistry | None = None,
    config: AuthzConfig | None = None,
) -> None:
    """Install ``do_orm_execute`` authorization on a session factory.

    After calling this, **all** SELECT queries through sessions created by
    this factory are automatically filtered by authorization policies.

    Works with both sync ``sessionmaker`` and async ``async_sessionmaker``.

    This is a thin convenience wrapper around
    :func:`sqla_authz.session.install_interceptor` that provides a
    FastAPI-friendly API surface.

    Args:
        session_factory: The ``sessionmaker`` or ``async_sessionmaker``
            to intercept.
        actor_provider: A callable returning the current actor.
            Called once per query execution.
        action: Default action string (e.g., ``"read"``).
            Can be overridden per-query via
            ``execution_options(authz_action="...")``.
        registry: Policy registry to use. Defaults to the global registry.
        config: :class:`~sqla_authz.config.AuthzConfig` to use.
            Defaults to the global config.

    Example::

        from sqlalchemy.orm import sessionmaker
        from sqla_authz.integrations.fastapi import install_authz_interceptor

        SessionLocal = sessionmaker(bind=engine)

        install_authz_interceptor(
            SessionLocal,
            actor_provider=get_current_user,
            action="read",
        )

        # All SELECT queries are now automatically filtered:
        with SessionLocal() as session:
            posts = session.execute(select(Post)).scalars().all()
            # Only authorized posts are returned
    """
    install_interceptor(
        session_factory,
        actor_provider=actor_provider,
        action=action,
        registry=registry,
        config=config,
    )
