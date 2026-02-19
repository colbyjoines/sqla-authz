# Audit Logging

`sqla_authz` emits structured log records for every policy evaluation. This lets you trace
exactly which policies matched, what filter expression was generated, and when no policy
was found for a given `(model, action)` pair.

## Enabling

Audit logging is disabled by default. Enable it globally with `configure()`:

```python
from sqla_authz import configure

configure(log_policy_decisions=True)
```

Or enable it for a specific session:

```python
from sqla_authz import authorized_sessionmaker
from sqla_authz.config import AuthzConfig

SessionLocal = authorized_sessionmaker(
    bind=engine,
    actor_provider=get_current_actor,
    config=AuthzConfig(log_policy_decisions=True),
)
```

## Log Levels

All records are emitted on the `"sqla_authz"` logger. The level indicates the outcome:

| Level | When | What's Included |
|-------|------|-----------------|
| `INFO` | Policy matched and evaluated successfully | Entity name, action, actor, policy count |
| `DEBUG` | Same as INFO, plus expression detail | All of the above + matched policy names + compiled filter expression |
| `WARNING` | No policy found for `(model, action)` | Entity name, action, actor, `on_missing_policy` setting |

`DEBUG` records are supersets of `INFO` records — configuring at `DEBUG` gives you everything.

## Logger Name

The logger is named `"sqla_authz"`. Configure it using the standard Python `logging` module:

```python
import logging

logging.getLogger("sqla_authz").setLevel(logging.DEBUG)
```

Because `sqla_authz` uses the standard `logging` hierarchy, it inherits handlers from the root
logger unless you configure it explicitly.

## What's Logged

Each log record includes the following fields in the message:

| Field | Description |
|-------|-------------|
| `entity` | The ORM model class name (e.g., `"Post"`) |
| `action` | The action string (e.g., `"read"`) |
| `actor` | String representation of the actor |
| `policy_count` | Number of policies that matched |
| `policy_names` | Names of matched policy functions (`DEBUG` only) |
| `filter_expression` | The compiled `ColumnElement[bool]` as SQL text (`DEBUG` only) |

When no policy is found (`WARNING`), the record also includes the `on_missing_policy` setting
so you can immediately see whether the query will return zero rows or raise `NoPolicyError`.

## Configuration Example

A complete logging setup for development — capturing all `sqla_authz` output:

```python
import logging
import logging.config

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "detailed": {
            "format": "%(asctime)s %(levelname)-8s %(name)s  %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "detailed",
            "stream": "ext://sys.stderr",
        },
    },
    "loggers": {
        "sqla_authz": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
}

logging.config.dictConfig(LOGGING)
```

With this configuration and `log_policy_decisions=True`, each query produces output similar to:

```
2026-02-19T12:00:01 INFO     sqla_authz  entity=Post action=read actor=User(id=42) policy_count=2
2026-02-19T12:00:01 DEBUG    sqla_authz  entity=Post action=read actor=User(id=42) policies=['owner_policy', 'public_policy'] filter=post.user_id = 42 OR post.is_public = true
```

A missing policy produces:

```
2026-02-19T12:00:02 WARNING  sqla_authz  entity=Comment action=delete actor=User(id=42) no_policy_found on_missing_policy=deny
```

## Production Considerations

Configure the logger at `WARNING` in production environments:

```python
# Production: only capture missing-policy warnings
logging.getLogger("sqla_authz").setLevel(logging.WARNING)
```

This catches the most actionable signal — queries with no registered policy — without generating
log volume for every successful evaluation.

Use `DEBUG` during development and `INFO` in staging when you want visibility into policy
evaluation without the overhead of compiling filter expressions to strings.

| Environment | Recommended Level | Reason |
|-------------|-------------------|--------|
| Production | `WARNING` | Catches missing policies; low volume |
| Staging / QA | `INFO` | Visibility into evaluations; no expression serialization |
| Development | `DEBUG` | Full detail including filter expressions |

!!! tip "Structured Logging Integration"
    If your application uses a structured logging library such as `structlog`, configure a handler
    on the `"sqla_authz"` logger that forwards records to your structured pipeline. The log message
    fields are consistently formatted as `key=value` pairs, making them easy to parse.
