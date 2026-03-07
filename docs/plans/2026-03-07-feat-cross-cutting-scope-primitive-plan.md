---
title: "feat: Add cross-cutting scope() primitive"
type: feat
status: completed
date: 2026-03-07
brainstorm: docs/brainstorms/2026-03-07-scope-primitive-brainstorm.md
---

# feat: Add cross-cutting scope() primitive

## Overview

Add a `scope()` decorator and `verify_scopes()` safety function to sqla-authz, enabling cross-cutting filters (tenant isolation, soft-delete, data residency) that are automatically AND'd with OR'd policy results. This is the P0 feature from `.docs/analysis.md`.

## Problem Statement

Every policy for every model in a multi-tenant app must independently include the tenant filter. Forgetting it on one model leaks data across tenants. The current library has no mechanism to enforce cross-cutting invariants — developers must copy-paste `Model.org_id == actor.org_id` into every policy function.

## Proposed Solution

A `@scope()` decorator that registers cross-cutting filter functions. Scopes are:
- AND'd with the OR'd policy result (scopes restrict, policies grant)
- Applied to explicit model lists via `applies_to=[...]`
- Active for all actions by default (optional `actions=` restriction)
- Integrated at `evaluate_policies()` — all three evaluation paths get scope support with one change

```python
@scope(applies_to=[Post, Comment, Document])
def tenant_scope(actor: User, Model: type) -> ColumnElement[bool]:
    return Model.org_id == actor.org_id
```

Final SQL: `WHERE (policy1 OR policy2) AND scope1 AND scope2`

## Technical Approach

### Integration Point

`evaluate_policies()` in `src/sqla_authz/compiler/_expression.py` is the single function where policies get OR'd. By AND'ing scopes here, all three paths get support automatically:

- `authorize_query()` — SQL WHERE clause injection
- `can()` / `authorize()` — in-memory point checks (evaluator handles AND natively)
- Session interceptor — automatic query filtering (calls `evaluate_policies()`)

**Zero changes needed** to: `_eval.py`, `_interceptor.py`, `_query.py`, `_checks.py`, `_safe_get.py`.

### Implementation Phases

#### Phase 1: Scope Registration Infrastructure

**New file: `src/sqla_authz/policy/_scope.py`**

Create `ScopeRegistration` dataclass (parallel to `PolicyRegistration` in `_base.py`):

```python
@dataclass(frozen=True, slots=True)
class ScopeRegistration:
    applies_to: tuple[type, ...]     # immutable copy of model list
    fn: Callable[..., ColumnElement[bool]]  # (actor, Model) -> filter
    name: str
    description: str
    actions: tuple[str, ...] | None  # None = all actions
```

Create `@scope` decorator in same file:

```python
def scope(
    applies_to: Sequence[type],
    *,
    actions: Sequence[str] | None = None,
    registry: PolicyRegistry | None = None,
) -> Callable[[F], F]:
```

- Validates `applies_to` is non-empty
- Validates function signature has at least 2 positional params (actor, Model)
- Registers via `registry.register_scope()`
- Returns original function unchanged

**Files to modify:**

| File | Change |
|------|--------|
| `src/sqla_authz/policy/_registry.py` | Add `_scopes` storage, `register_scope()`, `lookup_scopes()`, `has_scopes()`, update `clear()` |
| `src/sqla_authz/policy/_base.py` | Add `ScopeRegistration` to `__all__` (or keep in `_scope.py`) |
| `src/sqla_authz/policy/__init__.py` | Re-export `scope`, `ScopeRegistration` |

**Registry additions (in `PolicyRegistry`):**

```python
# Storage (keyed by model class, not by action)
_scopes: dict[type, list[ScopeRegistration]]

# Register a scope for all models in applies_to
def register_scope(self, scope_reg: ScopeRegistration) -> None

# Look up scopes for a model, filtered by action
def lookup_scopes(self, resource_type: type, action: str | None = None) -> list[ScopeRegistration]

# Check if any scopes exist for a model
def has_scopes(self, resource_type: type) -> bool

# clear() already exists — update to also clear _scopes
```

`lookup_scopes()` must:
1. Return all scopes where `resource_type` is in `scope.applies_to`
2. If `action` is provided and scope has `actions` restriction, only include if action is in `scope.actions`
3. If scope has `actions=None`, always include (applies to all actions)

#### Phase 2: Scope Evaluation in Expression Compiler

**File to modify: `src/sqla_authz/compiler/_expression.py`**

Update `evaluate_policies()` to AND scopes after OR'ing policies:

```python
def evaluate_policies(registry, resource_type, action, actor) -> ColumnElement[bool]:
    policies = registry.lookup(resource_type, action)

    if not policies:
        # ... existing deny-by-default logic (unchanged) ...
        return false()

    # Existing: OR all policies
    filters = [p.fn(actor) for p in policies]
    result = reduce(lambda a, b: a | b, filters)

    # NEW: AND all matching scopes
    scopes = registry.lookup_scopes(resource_type, action)
    for scope_reg in scopes:
        scope_expr = scope_reg.fn(actor, resource_type)
        result = result & scope_expr

    # ... existing audit logging (unchanged) ...
    return result
```

**Critical behavior:** When no policies exist, `false()` is returned regardless of scopes. Scopes are restrictions on top of policies, not replacements. This preserves fail-closed semantics.

#### Phase 3: verify_scopes() Safety Net

**New file: `src/sqla_authz/_verify.py`**

```python
def verify_scopes(
    base: type,
    *,
    field: str | None = None,
    when: Callable[[type], bool] | None = None,
    registry: PolicyRegistry | None = None,
) -> None:
```

- Scans all subclasses of `base` (SQLAlchemy `DeclarativeBase`)
- If `field` provided: checks if model has a column with that name (via `sqlalchemy.inspect`)
- If `when` provided: calls predicate with model class
- For each matching model, checks `registry.has_scopes(model)`
- Raises `UnscopedModelError` (new exception) listing all unscoped models
- `field` and `when` are mutually exclusive (raise `ValueError` if both provided)

**Files to modify:**

| File | Change |
|------|--------|
| `src/sqla_authz/exceptions.py` | Add `UnscopedModelError(AuthzError)` |
| `src/sqla_authz/__init__.py` | Add `scope`, `verify_scopes`, `UnscopedModelError` to imports and `__all__` |
| `tests/test_public_api.py` | Update `EXPECTED` sets |

#### Phase 4: Testing Isolation Update

**File to modify: `src/sqla_authz/testing/_isolation.py`**

`isolated_authz()` context manager saves/restores `_policies` directly. Must also save/restore `_scopes`:

```python
# Save
saved_scopes = dict(registry._scopes)  # shallow copy of dict

# Restore
registry._scopes.clear()
registry._scopes.update(saved_scopes)
```

#### Phase 5: Public API and Exports

**Files to modify:**

| File | Change |
|------|--------|
| `src/sqla_authz/__init__.py` | Import and export `scope`, `verify_scopes`, `UnscopedModelError` |
| `src/sqla_authz/policy/__init__.py` | Re-export `scope`, `ScopeRegistration` |
| `tests/test_public_api.py` | Add new symbols to `EXPECTED` sets |

## System-Wide Impact

- **authorize_query()**: No code changes. Gets scopes via `evaluate_policies()`.
- **can() / authorize()**: No code changes. In-memory evaluator handles AND natively.
- **Session interceptor**: No code changes. Calls `evaluate_policies()` which returns scoped expressions.
- **with_loader_criteria**: Already applied in interceptor using `evaluate_policies()` output — scopes are included automatically.
- **explain_access / explain_query**: Will show scope filters in output with no changes needed (they compile the expression to SQL).
- **testing/_simulation.py**: `simulate_query()` and `policy_matrix()` will reflect scopes in output. Defer scope-specific helpers to follow-up.
- **testing/_isolation.py**: Must save/restore `_scopes` — explicit change needed.

## Acceptance Criteria

### Functional Requirements

- [x] `@scope(applies_to=[...])` registers a cross-cutting filter function
- [x] Scope function receives `(actor, Model)` and returns `ColumnElement[bool]`
- [x] Scopes are AND'd with OR'd policy result in `evaluate_policies()`
- [x] Multiple scopes on same model are AND'd together
- [x] `actions=` parameter restricts scope to specific actions
- [x] Scope with `actions=None` applies to all actions
- [x] Scope function returning `true()` effectively bypasses the scope (admin use case)
- [x] No policies + scope = `false()` (fail-closed preserved)
- [x] `registry.clear()` clears both policies and scopes
- [x] `verify_scopes(Base, field="org_id")` raises for unscoped models
- [x] `verify_scopes(Base, when=predicate)` supports custom matching
- [x] `scope` and `verify_scopes` exported from `sqla_authz` top-level
- [x] Works with custom `registry=` parameter (non-global registries)

### Integration Requirements

- [x] `authorize_query()` produces correct SQL with scopes (no code changes to `_query.py`)
- [x] `can()` correctly evaluates scoped expressions in-memory (no code changes to `_eval.py`)
- [x] Session interceptor applies scopes automatically (no code changes to `_interceptor.py`)
- [x] `isolated_authz()` saves/restores scopes between tests

### Testing Requirements

- [x] Unit tests for `ScopeRegistration` dataclass
- [x] Unit tests for `register_scope()`, `lookup_scopes()`, `has_scopes()`, `clear()`
- [x] Unit tests for `@scope` decorator (registration, validation, signature checking)
- [x] Unit tests for scope composition in `evaluate_policies()` (AND semantics)
- [x] Unit tests for action-restricted scopes (`actions=["read"]`)
- [x] Unit tests for scope bypass (`true()` return)
- [x] Unit tests for no-policy-with-scope (fail-closed)
- [x] Unit tests for `verify_scopes()` (field-based and predicate-based)
- [x] Integration test: `authorize_query()` with scopes produces correct SQL
- [x] Integration test: `can()` with scopes evaluates correctly in-memory
- [x] Integration test: session interceptor applies scopes
- [x] Integration test: multi-tenant scenario (org_id scoping)
- [x] Thread safety test: concurrent scope registration
- [x] `test_public_api.py` updated and passing

## New Files

| File | Purpose |
|------|---------|
| `src/sqla_authz/policy/_scope.py` | `ScopeRegistration` dataclass + `@scope` decorator |
| `src/sqla_authz/_verify.py` | `verify_scopes()` standalone safety function |
| `tests/test_policy/test_scope.py` | Scope decorator + registration tests |
| `tests/test_compiler/test_scope_expression.py` | Scope AND'ing in `evaluate_policies()` tests |
| `tests/test_verify_scopes.py` | `verify_scopes()` safety net tests |

## Modified Files

| File | Lines | Change |
|------|-------|--------|
| `src/sqla_authz/policy/_registry.py:52-54` | Add `_scopes` dict to `__init__`, add `register_scope()`, `lookup_scopes()`, `has_scopes()` methods, update `clear()` |
| `src/sqla_authz/compiler/_expression.py:42-73` | AND scope expressions after OR'd policy result in `evaluate_policies()` |
| `src/sqla_authz/exceptions.py` | Add `UnscopedModelError` exception class |
| `src/sqla_authz/policy/__init__.py` | Re-export `scope`, `ScopeRegistration` |
| `src/sqla_authz/__init__.py` | Import/export `scope`, `verify_scopes`, `UnscopedModelError` |
| `src/sqla_authz/testing/_isolation.py` | Save/restore `_scopes` in `isolated_authz()` |
| `tests/test_public_api.py` | Update `EXPECTED` sets with new symbols |

## Dependencies & Risks

- **No breaking changes**: Scopes are purely additive. Existing policies, queries, and tests continue to work unchanged.
- **No new dependencies**: Uses existing SQLAlchemy types (`ColumnElement[bool]`, `true()`, `false()`).
- **Thread safety**: Scope registration uses the existing `threading.Lock` in `PolicyRegistry`.
- **Typed actions compatibility**: `actions=` parameter accepts `str`. When typed actions (RFC-001) land, `Action` is a `NewType("Action", str)` — compatible without changes.
- **Risk: scope function exceptions**: If a scope function raises, it propagates to the caller (same as policy functions). No special handling needed — same error model.

## References

- **Brainstorm**: `docs/brainstorms/2026-03-07-scope-primitive-brainstorm.md`
- **Analysis (Issue #2)**: `.docs/analysis.md` lines 26-37, 96-113
- **Integration point**: `src/sqla_authz/compiler/_expression.py:16-73`
- **Policy decorator pattern**: `src/sqla_authz/policy/_decorator.py:20-71`
- **Registry pattern**: `src/sqla_authz/policy/_registry.py:40-258`
- **In-memory evaluator**: `src/sqla_authz/compiler/_eval.py:127-163` (AND/OR handling)
- **Test isolation**: `src/sqla_authz/testing/_isolation.py`
