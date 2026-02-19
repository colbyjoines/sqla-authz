# Session Interception

Automatic authorization on every query — without calling `authorize_query()` explicitly.

## Overview

`sqla_authz` can intercept all SQLAlchemy SELECT statements automatically using SQLAlchemy's
[`do_orm_execute`](https://docs.sqlalchemy.org/en/20/orm/events.html#sqlalchemy.orm.SessionEvents.do_orm_execute)
event hook. When the interceptor is installed, every ORM query is filtered through your registered
policies before any rows are returned.

This is opt-in. You must explicitly install the interceptor — it does not activate automatically.

!!! warning "Explicit is Recommended"
    Automatic interception can be surprising in large codebases. Authorization silently filters rows,
    which can be difficult to debug. Start with [`authorize_query()`](../reference/api.md) and
    switch to interception once you understand query boundaries.

## `authorized_sessionmaker()`

The convenience factory creates a `sessionmaker` with the interceptor pre-installed.

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqla_authz import authorized_sessionmaker

engine = create_engine("postgresql+psycopg2://user:pass@localhost/mydb")

def get_current_actor():
    # Return the currently authenticated actor, e.g. from a context variable
    return current_user.get()

SessionLocal = authorized_sessionmaker(
    bind=engine,
    actor_provider=get_current_actor,
    action="read",       # default action applied to all queries
)
```

Every `Session` created from `SessionLocal` automatically applies authorization filters.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `bind` | `Engine` | SQLAlchemy engine to bind to |
| `actor_provider` | `Callable[[], ActorLike]` | Called per-query to resolve the current actor |
| `action` | `str` | Default action string (default: `"read"`) |
| `registry` | `PolicyRegistry \| None` | Custom registry; uses global registry if `None` |
| `config` | `AuthzConfig \| None` | Per-session config override |
| `**kwargs` | | Forwarded to `sessionmaker()` |

## `install_interceptor()`

Lower-level API for adding interception to an existing `sessionmaker`.

```python
from sqlalchemy.orm import sessionmaker
from sqla_authz.session import install_interceptor

SessionLocal = sessionmaker(bind=engine)

install_interceptor(
    SessionLocal,
    actor_provider=get_current_actor,
    action="read",
)
```

Use `install_interceptor()` when you need to configure the `sessionmaker` separately, or when
integrating into a framework that manages session factories for you.

## How It Works

When a query executes, the `do_orm_execute` event fires. The interceptor:

1. Receives the `ORMExecuteState` context.
2. Calls `actor_provider()` to resolve the current actor.
3. Looks up registered policies for each entity in the query.
4. Compiles policies to `ColumnElement[bool]` filter expressions.
5. Re-executes the statement with filters applied via `with_loader_criteria()`.

**Async sessions**: `do_orm_execute` fires on the inner synchronous session, even when using
`AsyncSession`. The event handler is always synchronous — this is a SQLAlchemy constraint. Policy
compilation is also synchronous (no I/O), so this works transparently for both sync and async usage.

The interceptor only modifies SELECT statements. INSERT, UPDATE, and DELETE queries pass through
unchanged.

## Skipping Authorization

Use `execution_options(skip_authz=True)` to bypass authorization for a specific query.

=== "Sync"

    ```python
    with SessionLocal() as session:
        # Admin query — skip authorization filters
        all_posts = (
            session.execute(
                select(Post).execution_options(skip_authz=True)
            )
            .scalars()
            .all()
        )
    ```

=== "Async"

    ```python
    async with AsyncSessionLocal() as session:
        # Admin query — skip authorization filters
        all_posts = (
            await session.execute(
                select(Post).execution_options(skip_authz=True)
            )
        ).scalars().all()
    ```

!!! tip "Skip for Admin Queries"
    Use `skip_authz=True` for administrative scripts, data migrations, and background jobs that
    should operate on all rows regardless of policy. Never expose this bypass to end-user request
    paths.

## Overriding Action Per-Query

Override the default action for a specific query using `execution_options(authz_action=...)`.

=== "Sync"

    ```python
    with SessionLocal() as session:
        # Check "update" policy instead of the session default "read"
        editable_posts = (
            session.execute(
                select(Post).execution_options(authz_action="update")
            )
            .scalars()
            .all()
        )
    ```

=== "Async"

    ```python
    async with AsyncSessionLocal() as session:
        editable_posts = (
            await session.execute(
                select(Post).execution_options(authz_action="update")
            )
        ).scalars().all()
    ```

This is useful when a single endpoint needs to check different policies — for example, listing
only the records a user can edit, not just read.

## Relationship Load Filtering

The interceptor uses `with_loader_criteria()` to propagate filters to relationship loads.
This means `selectinload`, `joinedload`, and lazy-loaded relationships are all filtered
through the same policies.

```python
from sqlalchemy.orm import selectinload

with SessionLocal() as session:
    # Both Post and related Comment rows are filtered by policy
    posts = (
        session.execute(
            select(Post).options(selectinload(Post.comments))
        )
        .scalars()
        .all()
    )
    # posts[0].comments only contains comments the actor can read
```

Without `with_loader_criteria()`, a plain `.where()` filter on the root query would not propagate
to eager or lazy loads. The interceptor handles this automatically.

## When to Use

| Approach | Best For |
|----------|----------|
| `authorize_query()` | Fine-grained control; recommended starting point |
| Session interception | Applications where every query must be authorized; reduces boilerplate |

Choose session interception when:

- All queries in your application should be authorized by default.
- You want to enforce authorization at the infrastructure layer, not in individual request handlers.
- You are building a multi-tenant application where row leakage is unacceptable.

Stick with `authorize_query()` when:

- You need to authorize different actions on different queries in the same request.
- Some queries legitimately bypass authorization (e.g., internal lookups).
- You want authorization decisions to be explicit and visible at the call site.
