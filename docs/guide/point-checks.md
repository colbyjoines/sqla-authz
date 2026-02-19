# Point Checks

Point checks answer a binary question: can this specific actor perform this specific action on this specific already-loaded object? They return a `bool` or raise an exception — no query is issued against your application database.

## When to Use

Use point checks when:

- You have a **single, already-loaded instance** and need a yes/no answer before acting on it.
- You are enforcing access in a mutation handler (create, update, delete) where you already fetched the resource.
- You want to conditionally show or hide a UI element based on whether an action is permitted.

Use [`authorize_query()`](../reference/api.md) instead when:

- You are fetching a **collection** — let the database do the filtering.
- You need **pagination** — `authorize_query` appends the WHERE clause before `LIMIT`/`OFFSET`, so counts are correct.
- Performance matters — point checks run a tiny SQLite query per call; `authorize_query` runs one query against your real database.

## can()

`can()` returns `True` if the actor is permitted, `False` otherwise:

```python
from sqla_authz import can

post = session.get(Post, post_id)

if can(actor, "delete", post):
    session.delete(post)
    session.commit()
else:
    raise PermissionError("Not allowed")
```

Full signature:

```python
def can(
    actor,
    action: str,
    resource,
    *,
    registry: PolicyRegistry | None = None,
) -> bool: ...
```

`registry` defaults to the global registry. Pass a custom one for test isolation.

## authorize()

`authorize()` is the raising variant. It returns `None` on success and raises `AuthorizationDenied` on failure:

```python
from sqla_authz import authorize
from sqla_authz.exceptions import AuthorizationDenied

post = session.get(Post, post_id)

try:
    authorize(actor, "edit", post)
except AuthorizationDenied as exc:
    return JSONResponse(status_code=403, content={"detail": str(exc)})

# Proceed with the edit
post.body = new_body
session.commit()
```

Full signature:

```python
def authorize(
    actor,
    action: str,
    resource,
    *,
    registry: PolicyRegistry | None = None,
    message: str | None = None,
) -> None: ...
```

`message` overrides the default exception message when you want to surface a specific error to the caller:

```python
authorize(actor, "publish", post, message="Only editors can publish posts.")
```

A common FastAPI pattern is to raise `HTTPException` directly:

```python
from fastapi import HTTPException

post = await session.get(Post, post_id)
if not can(actor, "edit", post):
    raise HTTPException(status_code=403, detail="Forbidden")
```

## How It Works

Point checks reuse the exact same policy functions registered with `@policy`. The evaluation sequence is:

1. Look up all policies registered for `(type(resource), action)` in the registry.
2. Call each policy function with the actor to obtain a `ColumnElement[bool]`.
3. OR the expressions together (same as `authorize_query`).
4. Open an **in-memory SQLite connection** (not your application database).
5. Insert a single row representing the resource instance into a temporary table.
6. Execute `SELECT 1 FROM tmp WHERE <compiled_filter>` against that row.
7. Return `True` if the row is returned, `False` otherwise.

Your application database is never touched. The temporary SQLite connection is created and destroyed within the call. There is no connection pooling or state shared between calls.

!!! warning "Performance"
    Each `can()` or `authorize()` call opens a temporary in-memory SQLite database, inserts a row, runs a query, and tears everything down. This overhead is negligible for occasional point checks in mutation handlers, but it adds up if called in a loop.

    **Never call `can()` or `authorize()` in a loop over a collection.** Use `authorize_query()` instead — it appends a single WHERE clause and lets the database do the filtering in one round-trip:

    ```python
    # Bad — N point checks, N temp SQLite DBs
    readable = [post for post in posts if can(actor, "read", post)]

    # Good — one query, one WHERE clause
    stmt = authorize_query(select(Post), actor=actor, action="read")
    readable = session.scalars(stmt).all()
    ```

## When to Use authorize_query() Instead

| Scenario | Recommended approach |
|---|---|
| Filtering a list of posts for display | `authorize_query()` |
| Paginated API endpoint returning posts | `authorize_query()` |
| Checking before deleting a single post | `can()` / `authorize()` |
| Showing/hiding an "Edit" button | `can()` |
| Bulk operations on a collection | `authorize_query()` — filter first, then act |

The guiding principle: if you need the database to return a filtered set of rows, use `authorize_query()`. If you have one object already in memory and need a decision, use `can()` or `authorize()`.
