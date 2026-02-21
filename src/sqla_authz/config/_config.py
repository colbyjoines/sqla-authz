"""Layered configuration for sqla-authz."""

from __future__ import annotations

from dataclasses import dataclass

from sqla_authz._types import (
    OnBypassAction,
    OnMissingPolicy,
    OnSkipAuthz,
    OnUnloadedRelationship,
    OnWriteDenied,
)

__all__ = [
    "AuthzConfig",
    "configure",
    "get_global_config",
    "_reset_global_config",
    "_set_global_config",
]

_VALID_POLICIES: set[str] = {"deny", "raise"}
_VALID_UNLOADED_RELATIONSHIP: set[str] = {"deny", "raise", "warn"}
_VALID_BYPASS_ACTIONS: set[str] = {"ignore", "warn", "raise"}
_VALID_SKIP_AUTHZ: set[str] = {"ignore", "warn", "log"}
_VALID_WRITE_DENIED: set[str] = {"raise", "filter"}


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

    on_missing_policy: OnMissingPolicy = "deny"
    default_action: str = "read"
    log_policy_decisions: bool = False
    on_unloaded_relationship: OnUnloadedRelationship = "deny"
    strict_mode: bool = False
    on_unprotected_get: OnBypassAction = "ignore"
    on_text_query: OnBypassAction = "ignore"
    on_skip_authz: OnSkipAuthz = "ignore"
    audit_bypasses: bool = False
    intercept_updates: bool = False
    intercept_deletes: bool = False
    on_write_denied: OnWriteDenied = "raise"

    def __post_init__(self) -> None:
        if self.on_missing_policy not in _VALID_POLICIES:
            raise ValueError(
                f"on_missing_policy must be one of {_VALID_POLICIES!r}, "
                f"got {self.on_missing_policy!r}"
            )
        if self.on_unloaded_relationship not in _VALID_UNLOADED_RELATIONSHIP:
            raise ValueError(
                f"on_unloaded_relationship must be one of "
                f"{_VALID_UNLOADED_RELATIONSHIP!r}, "
                f"got {self.on_unloaded_relationship!r}"
            )
        if self.on_unprotected_get not in _VALID_BYPASS_ACTIONS:
            raise ValueError(
                f"on_unprotected_get must be one of {_VALID_BYPASS_ACTIONS!r}, "
                f"got {self.on_unprotected_get!r}"
            )
        if self.on_text_query not in _VALID_BYPASS_ACTIONS:
            raise ValueError(
                f"on_text_query must be one of {_VALID_BYPASS_ACTIONS!r}, "
                f"got {self.on_text_query!r}"
            )
        if self.on_skip_authz not in _VALID_SKIP_AUTHZ:
            raise ValueError(
                f"on_skip_authz must be one of {_VALID_SKIP_AUTHZ!r}, got {self.on_skip_authz!r}"
            )
        if self.on_write_denied not in _VALID_WRITE_DENIED:
            raise ValueError(
                f"on_write_denied must be one of {_VALID_WRITE_DENIED!r}, "
                f"got {self.on_write_denied!r}"
            )
        # Apply strict_mode convenience defaults when individual settings
        # are left at their default "ignore" values.
        if self.strict_mode:
            defaults_applied: dict[str, str | bool] = {}
            if self.on_unprotected_get == "ignore":
                defaults_applied["on_unprotected_get"] = "warn"
            if self.on_text_query == "ignore":
                defaults_applied["on_text_query"] = "warn"
            if self.on_skip_authz == "ignore":
                defaults_applied["on_skip_authz"] = "log"
            if not self.audit_bypasses:
                defaults_applied["audit_bypasses"] = True
            if defaults_applied:
                # Use object.__setattr__ because the dataclass is frozen
                for attr, val in defaults_applied.items():
                    object.__setattr__(self, attr, val)

    def merge(
        self,
        *,
        on_missing_policy: OnMissingPolicy | None = None,
        default_action: str | None = None,
        log_policy_decisions: bool | None = None,
        on_unloaded_relationship: OnUnloadedRelationship | None = None,
        strict_mode: bool | None = None,
        on_unprotected_get: OnBypassAction | None = None,
        on_text_query: OnBypassAction | None = None,
        on_skip_authz: OnSkipAuthz | None = None,
        audit_bypasses: bool | None = None,
        intercept_updates: bool | None = None,
        intercept_deletes: bool | None = None,
        on_write_denied: OnWriteDenied | None = None,
    ) -> AuthzConfig:
        """Return a new config with non-None overrides applied.

        Args:
            on_missing_policy: Override for on_missing_policy (ignored if None).
            default_action: Override for default_action (ignored if None).
            log_policy_decisions: Override for log_policy_decisions (ignored if None).
            on_unloaded_relationship: Override for on_unloaded_relationship (ignored if None).
            strict_mode: Override for strict_mode (ignored if None).
            on_unprotected_get: Override for on_unprotected_get (ignored if None).
            on_text_query: Override for on_text_query (ignored if None).
            on_skip_authz: Override for on_skip_authz (ignored if None).
            audit_bypasses: Override for audit_bypasses (ignored if None).
            intercept_updates: Override for intercept_updates (ignored if None).
            intercept_deletes: Override for intercept_deletes (ignored if None).
            on_write_denied: Override for on_write_denied (ignored if None).

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
            on_unloaded_relationship=(
                on_unloaded_relationship
                if on_unloaded_relationship is not None
                else self.on_unloaded_relationship
            ),
            strict_mode=(strict_mode if strict_mode is not None else self.strict_mode),
            on_unprotected_get=(
                on_unprotected_get if on_unprotected_get is not None else self.on_unprotected_get
            ),
            on_text_query=(on_text_query if on_text_query is not None else self.on_text_query),
            on_skip_authz=(on_skip_authz if on_skip_authz is not None else self.on_skip_authz),
            audit_bypasses=(audit_bypasses if audit_bypasses is not None else self.audit_bypasses),
            intercept_updates=(
                intercept_updates if intercept_updates is not None else self.intercept_updates
            ),
            intercept_deletes=(
                intercept_deletes if intercept_deletes is not None else self.intercept_deletes
            ),
            on_write_denied=(
                on_write_denied if on_write_denied is not None else self.on_write_denied
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
    on_missing_policy: OnMissingPolicy | None = None,
    default_action: str | None = None,
    log_policy_decisions: bool | None = None,
    on_unloaded_relationship: OnUnloadedRelationship | None = None,
    strict_mode: bool | None = None,
    on_unprotected_get: OnBypassAction | None = None,
    on_text_query: OnBypassAction | None = None,
    on_skip_authz: OnSkipAuthz | None = None,
    audit_bypasses: bool | None = None,
    intercept_updates: bool | None = None,
    intercept_deletes: bool | None = None,
    on_write_denied: OnWriteDenied | None = None,
) -> AuthzConfig:
    """Update the global configuration by merging overrides.

    Only non-None values are applied. Returns the new global config.

    Args:
        on_missing_policy: Set to ``"deny"`` or ``"raise"``.
        default_action: Set the default action string.
        log_policy_decisions: Enable/disable audit logging of policy decisions.
        on_unloaded_relationship: Set to ``"deny"``, ``"raise"``, or ``"warn"``.
        strict_mode: Enable strict mode (applies convenience defaults).
        on_unprotected_get: Set to ``"ignore"``, ``"warn"``, or ``"raise"``.
        on_text_query: Set to ``"ignore"``, ``"warn"``, or ``"raise"``.
        on_skip_authz: Set to ``"ignore"``, ``"warn"``, or ``"log"``.
        audit_bypasses: Enable/disable bypass audit logging.
        intercept_updates: Enable interception of UPDATE statements.
        intercept_deletes: Enable interception of DELETE statements.
        on_write_denied: Set to ``"raise"`` or ``"filter"``.

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
        on_unloaded_relationship=on_unloaded_relationship,
        strict_mode=strict_mode,
        on_unprotected_get=on_unprotected_get,
        on_text_query=on_text_query,
        on_skip_authz=on_skip_authz,
        audit_bypasses=audit_bypasses,
        intercept_updates=intercept_updates,
        intercept_deletes=intercept_deletes,
        on_write_denied=on_write_denied,
    )
    return _global_config


def _set_global_config(cfg: AuthzConfig) -> None:
    """Replace global config with an exact snapshot. For testing only."""
    global _global_config
    _global_config = cfg


def _reset_global_config() -> None:
    """Reset global config to defaults. For testing only."""
    global _global_config
    _global_config = AuthzConfig()
