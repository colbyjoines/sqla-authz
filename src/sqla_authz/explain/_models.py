"""Data models for explain/dry-run output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "AccessExplanation",
    "AccessPolicyEvaluation",
    "AuthzExplanation",
    "EntityExplanation",
    "PolicyEvaluation",
]


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    """Result of evaluating a single policy for a query explanation.

    Attributes:
        name: Policy function name.
        description: Human-readable description.
        filter_expression: String representation of the filter expression.
        filter_sql: Compiled SQL with literal binds.
    """

    name: str
    description: str
    filter_expression: str
    filter_sql: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "filter_expression": self.filter_expression,
            "filter_sql": self.filter_sql,
        }


@dataclass(frozen=True, slots=True)
class EntityExplanation:
    """Explanation of how authorization filters apply to a single entity.

    Attributes:
        entity_name: Short class name (e.g. ``"Post"``).
        entity_type: Fully qualified class name.
        action: The action being explained.
        policies_found: Number of policies found for this entity/action.
        policies: Individual policy evaluations.
        combined_filter_sql: SQL for the combined (OR'd) filter.
        deny_by_default: True if no policies were found.
    """

    entity_name: str
    entity_type: str
    action: str
    policies_found: int
    policies: list[PolicyEvaluation]
    combined_filter_sql: str
    deny_by_default: bool

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""
        return {
            "entity_name": self.entity_name,
            "entity_type": self.entity_type,
            "action": self.action,
            "policies_found": self.policies_found,
            "policies": [p.to_dict() for p in self.policies],
            "combined_filter_sql": self.combined_filter_sql,
            "deny_by_default": self.deny_by_default,
        }


@dataclass(frozen=True, slots=True)
class AuthzExplanation:
    """Full explanation of how authorization filters would be applied to a SELECT.

    Attributes:
        action: The action being explained.
        actor_repr: String representation of the actor.
        entities: Per-entity explanations.
        authorized_sql: The fully authorized SQL statement.
        has_deny_by_default: True if any entity has no policies.
    """

    action: str
    actor_repr: str
    entities: list[EntityExplanation]
    authorized_sql: str
    has_deny_by_default: bool

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""
        return {
            "action": self.action,
            "actor_repr": self.actor_repr,
            "entities": [e.to_dict() for e in self.entities],
            "authorized_sql": self.authorized_sql,
            "has_deny_by_default": self.has_deny_by_default,
        }

    def __str__(self) -> str:
        """Return a human-readable multi-line explanation."""
        lines: list[str] = []
        lines.append(f"Authorization Explanation for action={self.action!r}")
        lines.append(f"  Actor: {self.actor_repr}")
        lines.append("")
        for entity in self.entities:
            lines.append(f"  Entity: {entity.entity_name}")
            if entity.deny_by_default:
                lines.append("    DENY BY DEFAULT (no policies registered)")
            else:
                lines.append(f"    Policies ({entity.policies_found}):")
                for p in entity.policies:
                    lines.append(f"      - {p.name}: {p.description}")
                    lines.append(f"        SQL: {p.filter_sql}")
                lines.append(f"    Combined SQL: {entity.combined_filter_sql}")
            lines.append("")
        lines.append(f"  Authorized SQL: {self.authorized_sql}")
        if self.has_deny_by_default:
            lines.append("  WARNING: Some entities have no policies (deny by default)")
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class AccessPolicyEvaluation:
    """Result of evaluating a single policy against a specific resource instance.

    Attributes:
        name: Policy function name.
        description: Human-readable description.
        filter_sql: Compiled SQL with literal binds.
        matched: Whether this policy matched the resource.
    """

    name: str
    description: str
    filter_sql: str
    matched: bool

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "filter_sql": self.filter_sql,
            "matched": self.matched,
        }


@dataclass(frozen=True, slots=True)
class AccessExplanation:
    """Explanation of why an actor can or cannot perform an action on a resource.

    Attributes:
        actor_repr: String representation of the actor.
        action: The action being checked.
        resource_type: Short class name of the resource.
        resource_repr: String representation of the resource instance.
        allowed: Whether access is allowed overall.
        deny_by_default: True if no policies were found.
        policies: Per-policy evaluation results.
    """

    actor_repr: str
    action: str
    resource_type: str
    resource_repr: str
    allowed: bool
    deny_by_default: bool
    policies: list[AccessPolicyEvaluation]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""
        return {
            "actor_repr": self.actor_repr,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_repr": self.resource_repr,
            "allowed": self.allowed,
            "deny_by_default": self.deny_by_default,
            "policies": [p.to_dict() for p in self.policies],
        }

    def __str__(self) -> str:
        """Return a human-readable multi-line explanation."""
        verdict = "ALLOWED" if self.allowed else "DENIED"
        lines: list[str] = []
        lines.append(f"Access Check: {verdict}")
        lines.append(f"  Actor: {self.actor_repr}")
        lines.append(f"  Action: {self.action}")
        lines.append(f"  Resource: {self.resource_type} ({self.resource_repr})")
        lines.append("")
        if self.deny_by_default:
            lines.append("  DENY BY DEFAULT (no policies registered)")
        else:
            lines.append("  Policy Results:")
            for p in self.policies:
                status = "MATCH" if p.matched else "NO MATCH"
                lines.append(f"    - {p.name} [{status}]: {p.description}")
                lines.append(f"      SQL: {p.filter_sql}")
        return "\n".join(lines)
