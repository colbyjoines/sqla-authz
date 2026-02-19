# Configuration

`sqla_authz` uses a layered configuration system: global defaults can be overridden per-session
and per-query.

## `AuthzConfig`

All configuration is held in an immutable `AuthzConfig` dataclass.

```python
from sqla_authz.config import AuthzConfig

config = AuthzConfig(
    on_missing_policy="deny",   # "deny" | "raise"
    default_action="read",
    log_policy_decisions=False,
)
```

`AuthzConfig` is frozen and slot-based — instances are safe to share across threads and
async contexts.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `on_missing_policy` | `str` | `"deny"` | Behavior when no policy matches `(model, action)` |
| `default_action` | `str` | `"read"` | Default action string for session interception |
| `log_policy_decisions` | `bool` | `False` | Emit audit log entries for each policy evaluation |

## `configure()`

Update the global configuration. Only non-`None` keyword arguments are applied — others remain
unchanged.

```python
from sqla_authz import configure

# Override just one setting; others stay at their defaults
configure(on_missing_policy="raise")

# Override multiple settings at once
configure(
    on_missing_policy="raise",
    log_policy_decisions=True,
)
```

`configure()` returns the updated `AuthzConfig` and modifies the global config in-place.
Call it once at application startup before any queries run.

## Layered Config

Configuration is resolved in three layers, each overriding the previous:

```
Global (configure()) → Session (authorized_sessionmaker / install_interceptor) → Query (execution_options)
```

Use `AuthzConfig.merge()` to produce a new config with selective overrides:

```python
from sqla_authz.config import AuthzConfig, get_global_config

global_cfg = get_global_config()

# Session-level override — raise on missing policy for this session
session_cfg = global_cfg.merge(on_missing_policy="raise")

# Query-level override — enable logging for one specific query
query_cfg = session_cfg.merge(log_policy_decisions=True)
```

`merge()` never mutates the original — it always returns a new `AuthzConfig`.

## `on_missing_policy`

Controls what happens when no registered policy matches a `(Model, action)` pair.

### `"deny"` (default)

The query receives `WHERE FALSE`, returning zero rows silently.

```python
configure(on_missing_policy="deny")

# No policy registered for (Post, "read")
posts = session.execute(select(Post)).scalars().all()
# posts == []  — silent empty result
```

### `"raise"`

Raises `NoPolicyError` immediately, before any SQL is executed.

```python
from sqla_authz.exceptions import NoPolicyError

configure(on_missing_policy="raise")

try:
    posts = session.execute(select(Post)).scalars().all()
except NoPolicyError as e:
    print(f"No policy for {e.model} / {e.action}")
```

!!! danger "Deny by Default"
    With `"deny"`, a missing or misspelled policy name silently returns zero rows. There is no
    error — queries just return nothing. Use `"raise"` during development to catch missing policies
    early. Switch to `"deny"` in production only after all policies are confirmed working.

## `default_action`

Sets the action string used when no explicit action is provided to the session interceptor or
`authorize_query()`.

```python
configure(default_action="read")
```

Override per-query with `execution_options(authz_action="update")`. See
[Session Interception — Overriding Action](session-interception.md#overriding-action-per-query).

## `log_policy_decisions`

Enable structured audit logging for every policy evaluation.

```python
configure(log_policy_decisions=True)
```

When enabled, each query evaluation emits log records on the `"sqla_authz"` logger. See
[Audit Logging](audit-logging.md) for log levels, format, and production guidance.

## Per-Session Override

Pass a custom `AuthzConfig` to `authorized_sessionmaker()` or `install_interceptor()` to override
the global config for all sessions created by that factory.

```python
from sqla_authz import authorized_sessionmaker
from sqla_authz.config import AuthzConfig

strict_config = AuthzConfig(on_missing_policy="raise", log_policy_decisions=True)

SessionLocal = authorized_sessionmaker(
    bind=engine,
    actor_provider=get_current_actor,
    config=strict_config,
)
```

The session-level config is merged on top of the global config. Fields not specified in
`strict_config` inherit from the global config at session-creation time.

## Testing

In tests, reset the global config to defaults between test cases to prevent state leakage.

```python
import pytest
from sqla_authz.config import _reset_global_config

@pytest.fixture(autouse=True)
def reset_config():
    yield
    _reset_global_config()
```

This is especially important when tests call `configure()` to simulate different environments
(e.g., testing behavior with `on_missing_policy="raise"` vs `"deny"`).
