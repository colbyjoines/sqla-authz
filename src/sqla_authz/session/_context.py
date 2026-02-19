"""AuthorizationContext — carries actor + action + config through the pipeline."""

from __future__ import annotations

from dataclasses import dataclass

from sqla_authz._types import ActorLike
from sqla_authz.config._config import AuthzConfig

__all__ = ["AuthorizationContext"]


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """Carries actor, action, and config through the authorization pipeline.

    Attributes:
        actor: The current user/principal satisfying ``ActorLike``.
        action: The action being performed (e.g., ``"read"``, ``"update"``).
        config: The resolved configuration for this authorization check.

    Example::

        ctx = AuthorizationContext(
            actor=current_user,
            action="read",
            config=AuthzConfig(),
        )
    """

    actor: ActorLike
    action: str
    config: AuthzConfig
