"""Layered configuration for sqla-authz."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["AuthzConfig", "configure", "get_global_config", "_reset_global_config"]


@dataclass(frozen=True, slots=True)
class AuthzConfig:
    """Layered configuration with merge semantics (global -> session -> query).

    Attributes:
        on_missing_policy: Behavior when no policy is registered.
            ``"deny"`` returns zero rows (WHERE FALSE).
            ``"raise"`` raises ``NoPolicyError``.
        default_action: The default action string used when none is specified.

    Example::

        config = AuthzConfig(on_missing_policy="raise")
        merged = config.merge(default_action="update")
    """

    on_missing_policy: str = "deny"
    default_action: str = "read"
    log_policy_decisions: bool = False

    def merge(
        self,
        *,
        on_missing_policy: str | None = None,
        default_action: str | None = None,
        log_policy_decisions: bool | None = None,
    ) -> AuthzConfig:
        """Return a new config with non-None overrides applied.

        Args:
            on_missing_policy: Override for on_missing_policy (ignored if None).
            default_action: Override for default_action (ignored if None).
            log_policy_decisions: Override for log_policy_decisions (ignored if None).

        Returns:
            A new ``AuthzConfig`` with overrides merged.

        Example::

            base = AuthzConfig()
            session_cfg = base.merge(on_missing_policy="raise")
            query_cfg = session_cfg.merge(default_action="update")
        """
        return AuthzConfig(
            on_missing_policy=(
                on_missing_policy if on_missing_policy is not None else self.on_missing_policy
            ),
            default_action=(default_action if default_action is not None else self.default_action),
            log_policy_decisions=(
                log_policy_decisions
                if log_policy_decisions is not None
                else self.log_policy_decisions
            ),
        )


# ---------------------------------------------------------------------------
# Global configuration singleton
# ---------------------------------------------------------------------------

_global_config = AuthzConfig()


def get_global_config() -> AuthzConfig:
    """Return the current global configuration.

    Example::

        config = get_global_config()
        print(config.on_missing_policy)  # "deny"
    """
    return _global_config


def configure(
    *,
    on_missing_policy: str | None = None,
    default_action: str | None = None,
    log_policy_decisions: bool | None = None,
) -> AuthzConfig:
    """Update the global configuration by merging overrides.

    Only non-None values are applied. Returns the new global config.

    Args:
        on_missing_policy: Set to ``"deny"`` or ``"raise"``.
        default_action: Set the default action string.
        log_policy_decisions: Enable/disable audit logging of policy decisions.

    Returns:
        The updated global ``AuthzConfig``.

    Example::

        configure(on_missing_policy="raise")
        # Now missing policies raise NoPolicyError instead of denying
    """
    global _global_config
    _global_config = _global_config.merge(
        on_missing_policy=on_missing_policy,
        default_action=default_action,
        log_policy_decisions=log_policy_decisions,
    )
    return _global_config


def _reset_global_config() -> None:
    """Reset global config to defaults. For testing only."""
    global _global_config
    _global_config = AuthzConfig()
