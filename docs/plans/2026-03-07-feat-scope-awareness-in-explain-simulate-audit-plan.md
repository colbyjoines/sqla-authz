---
title: "feat: Add scope awareness to explain, simulate, and audit systems"
type: feat
status: completed
date: 2026-03-07
---

# feat: Add scope awareness to explain, simulate, and audit systems

## Overview

The `@scope()` primitive is fully integrated into `evaluate_policies()` and `authorize_query()`, but three diagnostic/debugging systems and one docstring were not updated to reflect scopes. This creates a gap where the SQL output is correct but the diagnostic tools don't report *why* scope filters appear.

## Problem Statement

1. **`explain_access()`** evaluates policies individually against a resource but ignores scopes entirely. A user debugging "why can't this actor see this row?" won't see that a scope filter is blocking access.

2. **`explain_query()`** OR's policies and applies them to the statement, but doesn't AND scopes. The `authorized_sql` in its output is missing scope filters, making it disagree with `authorize_query()`.

3. **`simulate_query()`** calls `authorize_query()` (which applies scopes), so the SQL is correct. But `SimulationResult.policies_applied` doesn't report scopes, so the metadata is incomplete.

4. **Audit logging** in `evaluate_policies()` logs the final `result_expr` (which includes scopes), but doesn't explicitly log which scopes were applied. At `DEBUG` level, seeing "scope `tenant` applied" is more useful than reverse-engineering it from the combined expression.

5. **`AuthzConfig.merge()` docstring** lists all parameters in its Args section but omits `on_unknown_action`.

## Proposed Changes

### 1. `explain_access()` -- `src/sqla_authz/explain/_access.py`

**Current behavior:** Evaluates each policy's `fn(actor)` individually against the resource in a temp SQLite DB. Returns `AccessExplanation` with per-policy match results.

**Change:** After evaluating policies, look up scopes for the resource type and evaluate each scope against the resource. Add scope results to the output.

- [x]Call `target_registry.lookup_scopes(resource_type, action)` after policy evaluation
- [x]For each scope, evaluate `scope_reg.fn(actor, resource_type)` and check against the temp DB row (same pattern as policies)
- [x]If any policy matched but a scope blocks the row, set `allowed=False`
- [x]Add `scopes` field to `AccessExplanation` dataclass (list of `AccessScopeEvaluation`)
- [x]Add `AccessScopeEvaluation` dataclass to `_models.py`:
  ```python
  @dataclass(frozen=True, slots=True)
  class AccessScopeEvaluation:
      name: str
      description: str
      filter_sql: str
      matched: bool
  ```
- [x]Update `AccessExplanation.__str__()` to include scope results
- [x]Update `AccessExplanation.to_dict()` to include scopes

**Logic change:**
```python
# After policy evaluation loop:
scope_evals = []
all_scopes_match = True
scopes = target_registry.lookup_scopes(resource_type, action)
for scope_reg in scopes:
    expr = scope_reg.fn(actor, resource_type)
    check_stmt = select(literal_column("1")).select_from(table).where(expr)
    row = conn.execute(check_stmt).first()
    matched = row is not None
    if not matched:
        all_scopes_match = False
    scope_evals.append(AccessScopeEvaluation(...))

# Final verdict: policies must match AND all scopes must match
allowed = any_matched and all_scopes_match
```

### 2. `explain_query()` -- `src/sqla_authz/explain/_query.py`

**Current behavior:** OR's policy expressions, applies to statement. Does not look up scopes.

**Change:** After OR'ing policies, AND scopes (matching `evaluate_policies()` logic).

- [x]Call `target_registry.lookup_scopes(entity, action)` after policy evaluation
- [x]AND each scope expression into `combined_expr`
- [x]Add scope information to `EntityExplanation`:
  - [x]Add `scopes_applied: int` field
  - [x]Add `scope_names: list[str]` field (or a list of `ScopeEvaluation` dataclasses)
- [x]Update `EntityExplanation.to_dict()` and `AuthzExplanation.__str__()` to show scopes
- [x]The `authorized_sql` will now match `authorize_query()` output

**Logic change (in the per-entity loop, after policy OR):**
```python
# AND scopes (same as evaluate_policies)
scopes = target_registry.lookup_scopes(entity, action)
scope_evals = []
for scope_reg in scopes:
    scope_expr = scope_reg.fn(actor, entity)
    combined_expr = combined_expr & scope_expr
    scope_evals.append(ScopeEvaluation(name=scope_reg.name, ...))

combined_sql = _compile_sql(combined_expr)
authorized_stmt = authorized_stmt.where(combined_expr)
# Note: apply the scoped combined_expr, not the unscoped one
```

**Important:** The current code applies `combined_expr` (unscoped) to `authorized_stmt` at line 98. This must change to apply the scoped expression instead. Otherwise the `authorized_sql` won't include scopes.

### 3. `simulate_query()` -- `src/sqla_authz/testing/_simulation.py`

**Current behavior:** `SimulationResult` has `policies_applied: dict[str, list[str]]` but no scope information. The `authorized_sql` is correct (scopes are applied via `authorize_query()`), but the metadata doesn't report them.

**Change:** Add `scopes_applied` field to `SimulationResult`.

- [x]Add `scopes_applied: dict[str, list[str]]` field to `SimulationResult` (model name -> scope names)
- [x]In `simulate_query()`, look up scopes for each entity and populate the field:
  ```python
  scopes_applied: dict[str, list[str]] = {}
  for desc in desc_list:
      entity = desc.get("entity")
      if entity is None:
          continue
      scopes = target_registry.lookup_scopes(entity, action)
      if scopes:
          scopes_applied[entity.__name__] = [s.name for s in scopes]
  ```
- [x]Update `SimulationResult.__str__()` to show scopes
- [x]Ensure backward compatibility: `scopes_applied` defaults to `{}` via `field(default_factory=dict)`

### 4. Audit logging -- `src/sqla_authz/_audit.py` + `src/sqla_authz/compiler/_expression.py`

**Current behavior:** `log_policy_evaluation()` logs policy names and the result expression. Scopes are included in `result_expr` but not called out.

**Change:** Add scope names to the DEBUG log line.

- [x]Add optional `scopes` parameter to `log_policy_evaluation()`:
  ```python
  def log_policy_evaluation(
      *,
      entity: type,
      action: str,
      actor: ActorLike,
      policies: Sequence[PolicyRegistration],
      result_expr: ColumnElement[bool],
      scopes: Sequence[ScopeRegistration] = (),
  ) -> None:
  ```
- [x]At DEBUG level, log scope names alongside policy names:
  ```python
  if scopes:
      scope_names = [s.name for s in scopes]
      logger.debug(
          "Scopes applied for %s.%s: %s",
          entity_name, action, scope_names,
      )
  ```
- [x]In `evaluate_policies()`, pass the scopes to `log_policy_evaluation()`:
  ```python
  log_policy_evaluation(
      entity=resource_type,
      action=action,
      actor=actor,
      policies=policies,
      result_expr=result,
      scopes=scopes,  # <-- add this
  )
  ```

### 5. `AuthzConfig.merge()` docstring -- `src/sqla_authz/config/_config.py`

**Current behavior:** The `merge()` docstring Args section lists all parameters through `on_write_denied` but omits `on_unknown_action`.

**Change:**

- [x]Add to `merge()` docstring Args section (after `on_write_denied` line 148):
  ```
  on_unknown_action: Override for on_unknown_action (ignored if None).
  ```
- [x]Add to `configure()` docstring Args section (after `on_write_denied` line 246):
  ```
  on_unknown_action: Set to ``"ignore"``, ``"warn"``, or ``"raise"``.
  ```

## Implementation Notes

### Ordering

Process in dependency order:
1. `_models.py` (new dataclasses first -- `AccessScopeEvaluation`, `EntityExplanation` changes)
2. `_audit.py` (add `scopes` parameter)
3. `_expression.py` (pass scopes to audit log)
4. `_access.py` (explain_access scope support)
5. `_query.py` (explain_query scope support)
6. `_simulation.py` (SimulationResult.scopes_applied)
7. `_config.py` (docstring fix)
8. Tests for all of the above

### Backward Compatibility

- All new fields on dataclasses use defaults (`scopes=field(default_factory=list)`, `scopes_applied=field(default_factory=dict)`)
- `log_policy_evaluation()` `scopes` parameter defaults to `()`
- No breaking changes to existing return types

### What NOT to change

- Don't change `evaluate_policies()` behavior -- scopes already work correctly there
- Don't change `authorize_query()` -- it delegates to `evaluate_policies()`
- Don't add scope support to `can()` / `authorize()` -- they already work via `evaluate_policies()`

### Test Files

- `tests/test_explain/` -- Add scope-aware tests for `explain_access()` and `explain_query()`
- `tests/test_simulation.py` or equivalent -- Add `scopes_applied` field assertions
- `tests/test_audit.py` or equivalent -- Assert scope names appear in DEBUG logs

### Post-Implementation Verification

- [x]`explain_access()` shows scope evaluations and correct verdict when scope blocks
- [x]`explain_query()` `authorized_sql` matches `authorize_query()` output when scopes are active
- [x]`simulate_query()` reports `scopes_applied` in metadata
- [x]DEBUG audit log shows scope names
- [x]All existing tests still pass (no regressions)
- [x]`merge()` and `configure()` docstrings list `on_unknown_action`

## References

### Source files to modify
- `src/sqla_authz/explain/_models.py` -- `AccessScopeEvaluation`, `EntityExplanation` fields
- `src/sqla_authz/explain/_access.py` -- scope evaluation loop
- `src/sqla_authz/explain/_query.py` -- scope AND'ing
- `src/sqla_authz/testing/_simulation.py` -- `SimulationResult.scopes_applied`
- `src/sqla_authz/_audit.py` -- `scopes` parameter
- `src/sqla_authz/compiler/_expression.py` -- pass scopes to audit
- `src/sqla_authz/config/_config.py` -- docstring fix

### Reference implementations (how scopes work today)
- `src/sqla_authz/compiler/_expression.py:61-65` -- scope AND'ing in `evaluate_policies()`
- `src/sqla_authz/policy/_registry.py` -- `lookup_scopes()` API
- `src/sqla_authz/policy/_scope.py` -- `ScopeRegistration` dataclass

### Existing tests with scope coverage
- `tests/test_compiler/test_scope_expression.py`
- `tests/test_policy/test_scope.py`
- `tests/test_verify_scopes.py`
- `tests/test_session/test_scope_interceptor.py`
