"""Isolation utilities for global authz state in tests."""

from __future__ import annotations

import contextlib
from collections.abc import Generator

from sqla_authz.config._config import AuthzConfig
from sqla_authz.config._config import (
    _reset_global_config as _reset_global_config,  # pyright: ignore[reportPrivateUsage]
)
from sqla_authz.config._config import (
    _set_global_config as _set_global_config,  # pyright: ignore[reportPrivateUsage]
)
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = ["isolated_authz"]


@contextlib.contextmanager
def isolated_authz(
    *,
    config: AuthzConfig | None = None,
    registry: PolicyRegistry | None = None,
) -> Generator[tuple[AuthzConfig, PolicyRegistry], None, None]:
    """Context manager that provides isolated global authz state.

    Saves the current global config and default registry state,
    optionally applies overrides, yields the effective config and
    a fresh (or provided) registry, and restores original state on exit.

    Always restores state, even if the body raises an exception.

    Args:
        config: Optional config to use during the isolated block.
            If None, resets to defaults.
        registry: Optional registry to use. If None, uses the
            default registry (cleared).

    Yields:
        A tuple of (AuthzConfig, PolicyRegistry) for the isolated scope.

    Example::

        with isolated_authz(config=AuthzConfig(on_missing_policy="raise")) as (cfg, reg):
            reg.register(Post, "read", my_fn, name="p", description="")
            # Global state is isolated here
        # Original state is restored
    """
    from sqla_authz.config._config import get_global_config

    # Save current state — exact snapshot
    saved_config = get_global_config()
    saved_registry = get_default_registry()
    saved_policies = dict(saved_registry._policies)  # pyright: ignore[reportPrivateUsage]
    # Deep-copy the lists so restore is exact
    saved_policies = {k: list(v) for k, v in saved_policies.items()}

    try:
        # Reset to clean state
        _reset_global_config()
        saved_registry.clear()

        # Apply overrides if provided — exact snapshot, not merge
        if config is not None:
            _set_global_config(config)

        effective_config = get_global_config()
        effective_registry = registry if registry is not None else saved_registry

        yield effective_config, effective_registry
    finally:
        # Restore original state — exact snapshot, bypasses merge/post_init
        _set_global_config(saved_config)
        saved_registry.clear()
        for key, regs in saved_policies.items():
            for reg in regs:
                saved_registry._policies.setdefault(key, []).append(reg)  # pyright: ignore[reportPrivateUsage]
