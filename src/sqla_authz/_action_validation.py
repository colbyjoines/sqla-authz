"""Action validation — shared logic for all consumption points."""

from __future__ import annotations

import logging
from difflib import get_close_matches

from sqla_authz.config._config import AuthzConfig, get_global_config
from sqla_authz.policy._registry import PolicyRegistry

__all__ = ["check_unknown_action"]

logger = logging.getLogger("sqla_authz.actions")


def check_unknown_action(
    registry: PolicyRegistry,
    action: str,
    *,
    config: AuthzConfig | None = None,
) -> None:
    """Validate that an action has at least one registered policy.

    Behavior is controlled by ``config.on_unknown_action``:

    - ``"ignore"``: No-op (current behavior, backward compatible)
    - ``"warn"``: Log a warning with known actions list
    - ``"raise"``: Raise ``UnknownActionError``

    Skips validation when the registry has no policies at all
    (avoids false positives during app startup / test setup).

    Args:
        registry: The policy registry to check against.
        action: The action string to validate.
        config: Optional config override. Defaults to global config.
    """
    effective_config = config if config is not None else get_global_config()

    if effective_config.on_unknown_action == "ignore":
        return

    known = registry.known_actions()

    # Don't validate against an empty registry (startup / test setup)
    if not known:
        return

    if action in known:
        return

    # Action is unknown — warn or raise
    suggestion = _suggest_action(action, known)
    msg = _format_message(action, sorted(known), suggestion)

    if effective_config.on_unknown_action == "warn":
        logger.warning(msg)
    else:
        from sqla_authz.exceptions import UnknownActionError

        raise UnknownActionError(
            action=action,
            known_actions=sorted(known),
            suggestion=suggestion,
        )


def _suggest_action(action: str, known: set[str]) -> str | None:
    """Return closest matching action name, or None."""
    matches = get_close_matches(action, known, n=1, cutoff=0.6)
    return matches[0] if matches else None


def _format_message(
    action: str, known: list[str], suggestion: str | None
) -> str:
    parts = [f"Action {action!r} has no registered policies."]
    if suggestion:
        parts.append(f"Did you mean {suggestion!r}?")
    parts.append(f"Known actions: {known}")
    return " ".join(parts)
