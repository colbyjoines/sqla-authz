# Plan 03: Type Safety & Config Validation Overhaul

## Status: Draft
## Priority: High (correctness + developer experience)

---

## Problem Summary

The library claims "pyright strict mode compatible" but has several gaps in type safety and runtime validation:

1. **Unvalidated config strings** -- `on_missing_policy: str` accepts any string; invalid values silently fall through to deny behavior
2. **No policy registration validation** -- `registry.register()` accepts any callable with no signature checking
3. **Thread safety** -- `PolicyRegistry` has a data race in `register()` (non-atomic check-then-append)
4. **Global singleton test isolation** -- Manual `clear()`/`_reset_global_config()` is fragile and easy to forget

---

## Issue 1: Unvalidated `on_missing_policy` Config String

### Current Behavior

```python
# _config.py line 26
on_missing_policy: str = "deny"
```

The field is typed as `str`, allowing any value. The only consumer is `_interceptor.py:62`:

```python
if target_config.on_missing_policy == "raise":
    raise NoPolicyError(...)
```

Any value other than `"raise"` (including `"banana"`, `"Raise"`, typos) silently falls through to deny behavior. No error is raised at configuration time.

### Fix

**Step 1: Add a type alias in `_types.py`**

```python
from typing import Literal
OnMissingPolicy = Literal["deny", "raise"]
```

**Step 2: Change `AuthzConfig` field type**

```python
# _config.py
from sqla_authz._types import OnMissingPolicy

@dataclass(frozen=True, slots=True)
class AuthzConfig:
    on_missing_policy: OnMissingPolicy = "deny"
    default_action: str = "read"
    log_policy_decisions: bool = False
```

**Step 3: Add `__post_init__` validation**

Since the dataclass is `frozen=True`, we use `object.__setattr__` is not needed -- we validate and raise before the object is usable. With frozen dataclasses, `__post_init__` runs after field assignment, so we can validate directly:

```python
def __post_init__(self) -> None:
    _valid_policies: set[str] = {"deny", "raise"}
    if self.on_missing_policy not in _valid_policies:
        raise ValueError(
            f"on_missing_policy must be one of {_valid_policies!r}, "
            f"got {self.on_missing_policy!r}"
        )
```

The runtime check catches cases where the value comes from untyped sources (config files, environment variables, JSON). The `Literal` type catches static type errors at analysis time.

**Step 4: Update `merge()` and `configure()` signatures**

```python
def merge(
    self,
    *,
    on_missing_policy: OnMissingPolicy | None = None,
    ...
) -> AuthzConfig: ...

def configure(
    *,
    on_missing_policy: OnMissingPolicy | None = None,
    ...
) -> AuthzConfig: ...
```

### Files Changed

| File | Change |
|------|--------|
| `src/sqla_authz/_types.py` | Add `OnMissingPolicy` type alias |
| `src/sqla_authz/config/_config.py` | Change field type, add `__post_init__`, update `merge()`/`configure()` signatures |
| `src/sqla_authz/session/_interceptor.py` | No change needed (already compares against `"raise"`) |

### Backward Compatibility

- **Breaking for invalid values**: Code passing `on_missing_policy="banana"` will now raise `ValueError` at construction time. This is intentional -- such code was silently broken before.
- **Non-breaking for valid values**: `"deny"` and `"raise"` continue to work identically.
- **Type narrowing**: Callers using `str` variables will get pyright errors. They need to narrow to the Literal type. This is a desirable strictness improvement.
- **Mitigation**: Consider accepting `str` at runtime and just validating, while keeping the static type as `Literal`. This way, existing code that passes plain strings still works at runtime but gets type warnings. The `__post_init__` validation handles this.

### Test Cases

1. `AuthzConfig(on_missing_policy="deny")` succeeds
2. `AuthzConfig(on_missing_policy="raise")` succeeds
3. `AuthzConfig(on_missing_policy="banana")` raises `ValueError`
4. `AuthzConfig(on_missing_policy="DENY")` raises `ValueError` (case-sensitive)
5. `AuthzConfig(on_missing_policy="")` raises `ValueError`
6. `config.merge(on_missing_policy="raise")` succeeds
7. `config.merge(on_missing_policy="invalid")` raises `ValueError` (pyright error too)
8. `configure(on_missing_policy="raise")` succeeds
9. `configure(on_missing_policy="invalid")` raises `ValueError`

---

## Issue 2: No Policy Registration Validation

### Current Behavior

```python
# _registry.py line 29-35
def register(
    self,
    resource_type: type,
    action: str,
    fn: Callable[..., ColumnElement[bool]],
    ...
) -> None:
```

The `fn` parameter is `Callable[..., ColumnElement[bool]]` -- the `...` means any arguments are accepted. A function with the wrong signature (e.g., `lambda: true()` with zero args, or `lambda a, b, c: true()` with three args) is accepted at registration time but fails at query time when called as `p.fn(actor)`.

### Fix

**Step 1: Add a `PolicyFunction` protocol in `_types.py`**

```python
from typing import Protocol

class PolicyFunction(Protocol):
    """Protocol for policy functions: (actor) -> ColumnElement[bool]."""
    def __call__(self, actor: ActorLike) -> ColumnElement[bool]: ...
```

**Step 2: Optional runtime signature validation in `register()`**

Add a `validate_signature` parameter (default `True`) that inspects the callable:

```python
import inspect

def register(
    self,
    resource_type: type,
    action: str,
    fn: Callable[..., ColumnElement[bool]],
    *,
    name: str,
    description: str,
    validate_signature: bool = True,
) -> None:
    if validate_signature:
        _validate_policy_signature(fn)
    ...
```

The validation function:

```python
def _validate_policy_signature(fn: Callable[..., ColumnElement[bool]]) -> None:
    """Validate that a policy function has the expected (actor) -> ... signature."""
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        return  # Can't inspect (builtins, C extensions) -- skip validation

    params = [
        p for p in sig.parameters.values()
        if p.default is inspect.Parameter.empty
        and p.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    if len(params) < 1:
        raise TypeError(
            f"Policy function {fn!r} must accept at least one positional "
            f"parameter (actor), but has signature {sig}"
        )
```

**Why not change the type to `PolicyFunction`?**

Changing the `register()` parameter type from `Callable[..., ColumnElement[bool]]` to `PolicyFunction` would be ideal for static checking but would be a breaking change for existing code that uses lambdas or functions with more specific actor types (e.g., `def my_policy(user: User) -> ...`). Since `User` is not `ActorLike`, pyright would reject it unless the user protocol-matches.

Instead, keep the runtime type as `Callable[..., ColumnElement[bool]]` and add the `PolicyFunction` protocol for documentation and optional static checking in user code.

**Step 3: Add `PolicyFunction` to `_types.py` `__all__`**

Export it so users can annotate their own functions if they want strict checking.

### Files Changed

| File | Change |
|------|--------|
| `src/sqla_authz/_types.py` | Add `PolicyFunction` protocol |
| `src/sqla_authz/policy/_registry.py` | Add `_validate_policy_signature()`, add `validate_signature` param to `register()` |
| `src/sqla_authz/policy/_decorator.py` | No change (calls `register()` which validates) |

### Backward Compatibility

- **Non-breaking**: `validate_signature=True` by default but the check is lenient (only rejects zero-arg callables). Functions with extra optional parameters still pass.
- **Escape hatch**: `validate_signature=False` disables the check for advanced use cases.
- **Predicate class**: `Predicate.__call__` takes `(self, actor)` -- after `inspect.signature`, the visible parameter is `(actor)`, which passes validation.

### Test Cases

1. `register(Post, "read", lambda actor: true(), ...)` succeeds (valid)
2. `register(Post, "read", lambda: true(), ...)` raises `TypeError` (no actor param)
3. `register(Post, "read", lambda a, b, c: true(), ...)` succeeds (extra params have no defaults, but at least 1 positional exists -- actually this should succeed since we only check >= 1)
4. `register(..., validate_signature=False)` with zero-arg lambda succeeds (validation skipped)
5. `Predicate` objects pass validation (has `(actor)` param on `__call__`)
6. Functions with `**kwargs` pass validation
7. Built-in callables that can't be inspected don't raise

---

## Issue 3: Thread Safety for `PolicyRegistry`

### Current Behavior

```python
# _registry.py lines 71-74
key = (resource_type, action)
if key not in self._policies:
    self._policies[key] = []
self._policies[key].append(registration)
```

This is a classic check-then-act race condition. Under concurrent `register()` calls with the same key:
- Thread A checks `key not in self._policies` (True), creates empty list
- Thread B checks `key not in self._policies` (True), creates empty list (overwriting A's)
- Thread A appends to the list
- Thread B appends to the list -- but A's registration is lost (it was in the overwritten list)

Under CPython's GIL this is unlikely but possible (GIL can release between the dict operations). Under free-threaded Python (PEP 703, Python 3.13t+), this is a genuine data race.

### Fix

**Add a `threading.Lock` to `PolicyRegistry`**

```python
import threading

class PolicyRegistry:
    def __init__(self) -> None:
        self._policies: dict[tuple[type, str], list[PolicyRegistration]] = {}
        self._lock = threading.Lock()

    def register(self, ...) -> None:
        registration = PolicyRegistration(...)
        key = (resource_type, action)
        with self._lock:
            if key not in self._policies:
                self._policies[key] = []
            self._policies[key].append(registration)

    def lookup(self, resource_type: type, action: str) -> list[PolicyRegistration]:
        with self._lock:
            return list(self._policies.get((resource_type, action), []))

    def has_policy(self, resource_type: type, action: str) -> bool:
        with self._lock:
            return (resource_type, action) in self._policies

    def registered_entities(self, action: str) -> set[type]:
        with self._lock:
            return {entity for entity, act in self._policies if act == action}

    def clear(self) -> None:
        with self._lock:
            self._policies.clear()
```

### Performance Impact Assessment

**Lock contention is negligible in practice:**

1. **Registration phase**: `register()` is called at startup/import time, not in hot paths. Lock overhead during startup is irrelevant.

2. **Read phase (hot path)**: `lookup()`, `has_policy()`, and `registered_entities()` are called per-query. A `threading.Lock` acquisition is ~50-100ns on modern hardware. Compared to the cost of a database query (milliseconds), this is noise -- less than 0.01% overhead.

3. **Alternative considered: `threading.RLock`**: Not needed since we have no recursive locking patterns.

4. **Alternative considered: Read-write lock**: Python's `threading` module doesn't provide one natively. A third-party `rwlock` would add a dependency. The standard `Lock` is sufficient given the negligible overhead.

5. **Alternative considered: Copy-on-write (immutable snapshots)**: Replace the dict with a frozen snapshot on each write, so reads need no lock. This is more complex and only worthwhile if profiling shows lock contention, which is extremely unlikely for this use case.

**Recommendation**: Use `threading.Lock` on all methods. Simple, correct, and the performance cost is unmeasurable relative to I/O.

### Files Changed

| File | Change |
|------|--------|
| `src/sqla_authz/policy/_registry.py` | Add `threading.Lock`, wrap all methods |

### Backward Compatibility

- **Fully backward compatible**: No API changes. Only internal synchronization added.

### Test Cases

1. Existing `test_concurrent_registration` should continue to pass (and now be formally correct)
2. Add a stress test: 100 threads doing concurrent `register()` + `lookup()` -- verify no lost registrations and no exceptions
3. Verify `clear()` under concurrent access doesn't raise

---

## Issue 4: Global Singleton Test Isolation

### Current Behavior

Tests must manually call `_reset_global_config()` and `registry.clear()` in setup/teardown:

```python
# test_config.py
def setup_method(self) -> None:
    _reset_global_config()

def teardown_method(self) -> None:
    _reset_global_config()
```

This is fragile:
- Easy to forget in new test classes
- Failure in a test can skip teardown, leaving polluted state
- The `_reset_global_config` function is a private API (leading underscore) used in tests

### Fix

**Step 1: Add a context manager for global state isolation**

```python
# src/sqla_authz/testing/_isolation.py

from __future__ import annotations

import contextlib
from collections.abc import Generator

from sqla_authz.config._config import AuthzConfig, _reset_global_config, configure
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry


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
        registry: Optional registry to use. If None, clears the
            default registry.

    Yields:
        A tuple of (AuthzConfig, PolicyRegistry) for the isolated scope.

    Example::

        with isolated_authz(config=AuthzConfig(on_missing_policy="raise")) as (cfg, reg):
            reg.register(Post, "read", my_fn, name="p", description="")
            # Global state is isolated here
        # Original state is restored
    """
    from sqla_authz.config._config import get_global_config

    # Save current state
    saved_config = get_global_config()
    saved_registry = get_default_registry()
    saved_policies = dict(saved_registry._policies)  # shallow copy of the dict

    try:
        # Reset to clean state
        _reset_global_config()
        saved_registry.clear()

        # Apply overrides if provided
        if config is not None:
            configure(
                on_missing_policy=config.on_missing_policy,
                default_action=config.default_action,
                log_policy_decisions=config.log_policy_decisions,
            )

        effective_config = get_global_config()
        effective_registry = registry if registry is not None else saved_registry

        yield effective_config, effective_registry
    finally:
        # Restore original state
        _reset_global_config()
        configure(
            on_missing_policy=saved_config.on_missing_policy,
            default_action=saved_config.default_action,
            log_policy_decisions=saved_config.log_policy_decisions,
        )
        saved_registry.clear()
        for key, regs in saved_policies.items():
            for reg in regs:
                saved_registry._policies.setdefault(key, []).append(reg)
```

**Step 2: Add a pytest fixture wrapping the context manager**

```python
# src/sqla_authz/testing/_fixtures.py

@pytest.fixture()
def isolated_authz_state() -> Generator[tuple[AuthzConfig, PolicyRegistry], None, None]:
    """Pytest fixture that isolates global authz state for each test.

    Resets global config and clears the default registry before the test,
    and restores original state after.

    Example::

        def test_something(isolated_authz_state):
            cfg, registry = isolated_authz_state
            registry.register(Post, "read", my_fn, name="p", description="")
    """
    from sqla_authz.testing._isolation import isolated_authz

    with isolated_authz() as state:
        yield state
```

**Step 3: Export from `testing` package and register in plugin**

Add to `_plugin.py` re-exports and `_fixtures.py` `__all__`.

### Files Changed

| File | Change |
|------|--------|
| `src/sqla_authz/testing/_isolation.py` | New file: `isolated_authz` context manager |
| `src/sqla_authz/testing/_fixtures.py` | Add `isolated_authz_state` fixture |
| `src/sqla_authz/testing/_plugin.py` | Re-export the new fixture |
| `src/sqla_authz/testing/__init__.py` | Export `isolated_authz` |

### Backward Compatibility

- **Fully backward compatible**: Additive change. Existing `_reset_global_config()` and `clear()` continue to work.
- **Migration path**: Existing tests can gradually adopt the new fixture. No forced migration.

### Test Cases

1. `isolated_authz` context manager resets config on entry
2. `isolated_authz` context manager restores config on exit
3. `isolated_authz` context manager restores config even on exception
4. `isolated_authz(config=AuthzConfig(on_missing_policy="raise"))` applies the override
5. `isolated_authz_state` fixture provides clean state per test
6. Two sequential tests using the fixture don't share state

---

## Implementation Order

Execute in this order to minimize risk and allow incremental testing:

### Phase 1: Type foundations (no behavior changes)
1. Add `OnMissingPolicy` type alias to `_types.py`
2. Add `PolicyFunction` protocol to `_types.py`

### Phase 2: Config validation (small behavior change)
4. Change `AuthzConfig.on_missing_policy` type to `OnMissingPolicy`
5. Add `__post_init__` validation
6. Update `merge()` and `configure()` signatures
7. Update tests for validation behavior

### Phase 3: Registry improvements
8. Add `threading.Lock` to `PolicyRegistry`
9. Add `_validate_policy_signature()` and `validate_signature` parameter
10. Update registry tests

### Phase 4: Test infrastructure
11. Create `_isolation.py` with context manager
12. Add `isolated_authz_state` fixture
13. Update plugin exports

### Phase 5: Verification
14. Run `uv run pyright src/sqla_authz/` -- must report 0 errors
15. Run full test suite
16. Run the concurrent registration stress test

---

## Full File Change Summary

| File | Type of Change | Issue(s) |
|------|---------------|----------|
| `src/sqla_authz/_types.py` | Add `OnMissingPolicy`, `PolicyFunction` | 1, 2 |
| `src/sqla_authz/config/_config.py` | Literal type, `__post_init__`, updated signatures | 1 |
| `src/sqla_authz/policy/_registry.py` | `threading.Lock`, `_validate_policy_signature` | 2, 3 |
| `src/sqla_authz/testing/_isolation.py` | New: `isolated_authz` context manager | 4 |
| `src/sqla_authz/testing/_fixtures.py` | Add `isolated_authz_state` fixture | 5 |
| `src/sqla_authz/testing/_plugin.py` | Re-export new fixture | 5 |
| `tests/test_config/test_config.py` | Add validation tests, update for Literal type | 1 |
| `tests/test_policy/test_registry.py` | Add signature validation + thread stress tests | 2, 3 |

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Existing code passes raw `str` to `on_missing_policy` | Pyright errors for callers | Runtime validation still accepts the string; pyright errors guide migration |
| `inspect.signature` fails on some callables | `TypeError` on registration | Catch `ValueError`/`TypeError` in `_validate_policy_signature` and skip |
| Lock overhead on hot read paths | Microsecond-level latency | Benchmarked at ~50-100ns per acquire; negligible vs DB I/O |
| `isolated_authz` accesses private `_policies` attribute | Fragile coupling | Document as internal; the alternative (re-registering via public API) is equally fragile |
| `__post_init__` on frozen dataclass | Edge case with inheritance | `frozen=True` supports `__post_init__` natively; no workaround needed |
