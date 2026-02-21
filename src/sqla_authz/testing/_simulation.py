"""Policy testing and simulation tools — matrix, simulate, diff, snapshot.

Provides database-free tools for verifying policy correctness,
detecting regressions, and understanding policy coverage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Select

from sqla_authz._types import ActorLike
from sqla_authz.compiler._expression import evaluate_policies
from sqla_authz.compiler._query import authorize_query
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = [
    "PolicyCoverage",
    "PolicyDiff",
    "PolicyMatrix",
    "SimulationResult",
    "assert_policy_sql_snapshot",
    "diff_policies",
    "policy_matrix",
    "simulate_query",
]


# ---------------------------------------------------------------------------
# policy_matrix — coverage matrix
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PolicyCoverage:
    """Coverage entry for a single (model, action) pair."""

    resource_type: str
    action: str
    policy_count: int
    policy_names: tuple[str, ...]


@dataclass
class PolicyMatrix:
    """Full coverage matrix for a registry."""

    entries: list[PolicyCoverage] = field(default_factory=lambda: [])

    @property
    def summary(self) -> str:
        """Human-readable coverage table."""
        lines = ["Model           | Action  | Policies | Names"]
        lines.append("-" * 60)
        for e in sorted(self.entries, key=lambda x: (x.resource_type, x.action)):
            names = ", ".join(e.policy_names) if e.policy_names else "(none)"
            lines.append(f"{e.resource_type:<15} | {e.action:<7} | {e.policy_count:<8} | {names}")
        return "\n".join(lines)

    @property
    def uncovered(self) -> list[PolicyCoverage]:
        """Return entries with zero policies (gaps)."""
        return [e for e in self.entries if e.policy_count == 0]


def policy_matrix(
    registry: PolicyRegistry | None = None,
    *,
    models: list[type] | None = None,
    actions: list[str] | None = None,
) -> PolicyMatrix:
    """Generate a coverage matrix showing which (model, action) pairs have policies.

    If models or actions are not provided, they are inferred from the
    registry's registered policies.

    Args:
        registry: The policy registry to analyze. Defaults to the global registry.
        models: Optional explicit list of models to check.
        actions: Optional explicit list of actions to check.

    Returns:
        A PolicyMatrix with one entry per (model, action) combination.

    Example::

        matrix = policy_matrix(registry, actions=["read", "update", "delete"])
        print(matrix.summary)
        assert len(matrix.uncovered) == 0, f"Uncovered: {matrix.uncovered}"
    """
    target_registry = registry if registry is not None else get_default_registry()

    # Access internal _policies dict to discover models/actions.
    # We read under the lock by calling lookup for safety, but need
    # the keys to discover what's registered.
    policy_keys = target_registry.registered_keys()

    if models is None:
        models = sorted(
            {rt for rt, _ in policy_keys},
            key=lambda m: m.__name__,
        )
    if actions is None:
        actions = sorted({act for _, act in policy_keys})

    entries: list[PolicyCoverage] = []
    for model in models:
        for action in actions:
            policies = target_registry.lookup(model, action)
            entries.append(
                PolicyCoverage(
                    resource_type=model.__name__,
                    action=action,
                    policy_count=len(policies),
                    policy_names=tuple(p.name for p in policies),
                )
            )

    return PolicyMatrix(entries=entries)


# ---------------------------------------------------------------------------
# simulate_query — SQL preview without execution
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SimulationResult:
    """Result of a query simulation."""

    original_sql: str
    authorized_sql: str
    actor_repr: str
    action: str
    policies_applied: dict[str, list[str]]

    def __str__(self) -> str:
        lines = [f"Simulation(actor={self.actor_repr}, action={self.action!r})"]
        lines.append(f"  Original:   {self.original_sql}")
        lines.append(f"  Authorized: {self.authorized_sql}")
        for entity, policies in self.policies_applied.items():
            lines.append(f"  {entity}: {', '.join(policies)}")
        return "\n".join(lines)


def simulate_query(
    stmt: Select[Any],
    *,
    actor: ActorLike,
    action: str,
    registry: PolicyRegistry | None = None,
) -> SimulationResult:
    """Show the SQL that would be produced by authorize_query, without executing.

    Args:
        stmt: The SELECT statement to authorize.
        actor: The actor to simulate as.
        action: The action string.
        registry: Optional custom registry.

    Returns:
        A SimulationResult containing the authorized SQL and metadata.

    Example::

        result = simulate_query(
            select(Post).where(Post.category == "tech"),
            actor=MockActor(id=42, role="editor"),
            action="read",
            registry=registry,
        )
        print(result.sql)
    """
    target_registry = registry if registry is not None else get_default_registry()

    authorized_stmt = authorize_query(stmt, actor=actor, action=action, registry=target_registry)

    compile_kwargs: dict[str, Any] = {"literal_binds": True}
    original_sql = str(stmt.compile(compile_kwargs=compile_kwargs))
    authorized_sql = str(authorized_stmt.compile(compile_kwargs=compile_kwargs))

    # Extract which policies were applied per entity
    policies_applied: dict[str, list[str]] = {}
    desc_list: list[dict[str, Any]] = stmt.column_descriptions
    for desc in desc_list:
        entity: type | None = desc.get("entity")
        if entity is None:
            continue
        policies = target_registry.lookup(entity, action)
        policies_applied[entity.__name__] = [p.name for p in policies]

    return SimulationResult(
        original_sql=original_sql,
        authorized_sql=authorized_sql,
        actor_repr=repr(actor),
        action=action,
        policies_applied=policies_applied,
    )


# ---------------------------------------------------------------------------
# diff_policies — policy change detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PolicyDiff:
    """Difference between two policy registries."""

    added: tuple[tuple[str, str, str], ...]
    removed: tuple[tuple[str, str, str], ...]
    changed_models: frozenset[str]

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed)

    def __str__(self) -> str:
        lines: list[str] = []
        for model, action, name in self.added:
            lines.append(f"  + {model}.{action}: {name}")
        for model, action, name in self.removed:
            lines.append(f"  - {model}.{action}: {name}")
        return "\n".join(lines) if lines else "  (no changes)"


def diff_policies(
    old: PolicyRegistry,
    new: PolicyRegistry,
) -> PolicyDiff:
    """Compare two registries and return the differences.

    Useful for CI/CD pipelines to detect policy changes across
    deployments or code reviews.

    Args:
        old: The baseline registry (e.g., from main branch).
        new: The updated registry (e.g., from feature branch).

    Returns:
        A PolicyDiff describing added and removed policies.

    Example::

        diff = diff_policies(old_registry, new_registry)
        if diff.has_changes:
            print(f"Policy changes detected:\\n{diff}")
    """
    old_keys = old.registered_keys()
    new_keys = new.registered_keys()

    added: list[tuple[str, str, str]] = []
    removed: list[tuple[str, str, str]] = []
    changed_models: set[str] = set()

    # Removed keys
    for key in old_keys - new_keys:
        model_name, action = key[0].__name__, key[1]
        for p in old.lookup(*key):
            removed.append((model_name, action, p.name))
            changed_models.add(model_name)

    # Added keys
    for key in new_keys - old_keys:
        model_name, action = key[0].__name__, key[1]
        for p in new.lookup(*key):
            added.append((model_name, action, p.name))
            changed_models.add(model_name)

    # Changed keys (same key, different policies)
    for key in old_keys & new_keys:
        model_name, action = key[0].__name__, key[1]
        old_names = {p.name for p in old.lookup(*key)}
        new_names = {p.name for p in new.lookup(*key)}
        for name in sorted(new_names - old_names):
            added.append((model_name, action, name))
            changed_models.add(model_name)
        for name in sorted(old_names - new_names):
            removed.append((model_name, action, name))
            changed_models.add(model_name)

    return PolicyDiff(
        added=tuple(added),
        removed=tuple(removed),
        changed_models=frozenset(changed_models),
    )


# ---------------------------------------------------------------------------
# assert_policy_sql_snapshot — regression testing
# ---------------------------------------------------------------------------


def assert_policy_sql_snapshot(
    registry: PolicyRegistry,
    resource_type: type,
    action: str,
    actor: ActorLike,
    *,
    snapshot: str,
    normalize_whitespace: bool = True,
) -> None:
    """Assert that the policy SQL matches a snapshot string.

    Useful for detecting unintended changes to generated SQL
    across code modifications.

    Args:
        registry: The policy registry.
        resource_type: The model class.
        action: The action string.
        actor: The actor to evaluate against.
        snapshot: The expected SQL string.
        normalize_whitespace: If True, collapse whitespace for comparison.

    Raises:
        AssertionError: If the actual SQL does not match the snapshot.

    Example::

        assert_policy_sql_snapshot(
            registry, Post, "read", MockActor(id=1),
            snapshot="post.is_published = true OR post.author_id = 1",
        )
    """
    filter_expr = evaluate_policies(registry, resource_type, action, actor)
    actual = str(filter_expr.compile(compile_kwargs={"literal_binds": True}))

    expected = snapshot
    if normalize_whitespace:
        actual = re.sub(r"\s+", " ", actual).strip()
        expected = re.sub(r"\s+", " ", expected).strip()

    if actual != expected:
        raise AssertionError(
            f"Policy SQL snapshot mismatch:\n  Expected: {expected}\n  Actual:   {actual}"
        )
