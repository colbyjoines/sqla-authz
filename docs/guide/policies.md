# Policies

A policy is a Python function decorated with `@policy` that takes an actor and returns a SQLAlchemy `ColumnElement[bool]`. That expression becomes the `WHERE` clause appended to your query — evaluated by the database, not in Python.

## Defining Policies

Use `@policy(Model, "action")` to register a function for a `(model, action)` pair:

```python title="Basic policy"
from sqlalchemy import ColumnElement
from sqla_authz import policy

@policy(Post, "read")
def post_read(actor) -> ColumnElement[bool]:
    return Post.is_published == True
```

When `authorize_query` runs against a `select(Post)` with `action="read"`, this function is called with the current actor and its return value is appended as a `WHERE` clause:

```sql
SELECT post.id, post.title, post.is_published
FROM post
WHERE post.is_published = true
```

## Policy Function Signature

A policy function receives the actor and must return a `ColumnElement[bool]`. The actor type is the `ActorLike` protocol — any object with an `id` attribute, or any custom type you use.

```python
from sqlalchemy import ColumnElement
from sqla_authz import policy
from sqla_authz._types import ActorLike

@policy(Post, "read")
def post_read(actor: ActorLike) -> ColumnElement[bool]:
    return Post.author_id == actor.id
```

If your actor has richer typing, use it directly:

```python
@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    return Post.author_id == actor.id
```

The function must be **synchronous** and must not perform I/O. Policy compilation is a pure Python transformation — the expression is built in memory and handed to SQLAlchemy to embed in the query.

## Python Control Flow

Policies are plain Python functions, so any control flow is valid. Only the final `ColumnElement[bool]` hits the database:

```python
from sqlalchemy import true, false, or_

@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    # Admins see everything
    if actor.role == "admin":
        return true()

    # Moderators see published posts plus posts in their section
    if actor.role == "moderator":
        return or_(
            Post.is_published == True,
            Post.section_id == actor.section_id,
        )

    # Regular users see only published posts they authored
    return or_(
        Post.is_published == True,
        Post.author_id == actor.id,
    )
```

The `if` branches run at query-build time in Python. Whichever branch is taken produces a single `ColumnElement[bool]` that becomes the WHERE clause. No Python-side row filtering occurs.

## Multiple Policies

Registering multiple `@policy` decorators for the same `(Model, action)` pair is supported. All matching policies are combined with `OR`:

```python
@policy(Post, "read")
def published_posts(actor: User) -> ColumnElement[bool]:
    return Post.is_published == True


@policy(Post, "read")
def own_drafts(actor: User) -> ColumnElement[bool]:
    return and_(
        Post.is_published == False,
        Post.author_id == actor.id,
    )
```

These two policies produce:

```sql
WHERE post.is_published = true
   OR (post.is_published = false AND post.author_id = :id)
```

This lets you decompose complex rules into small, individually testable functions and compose them by registration.

## true() and false()

`sqlalchemy.true()` and `sqlalchemy.false()` are the allow-all and deny-all constants:

```python
from sqlalchemy import true, false

# Allow everyone unconditionally
@policy(Post, "read")
def allow_all(actor) -> ColumnElement[bool]:
    return true()

# Deny everyone unconditionally (useful for temporarily locking down a resource)
@policy(Post, "delete")
def deny_all(actor) -> ColumnElement[bool]:
    return false()
```

`true()` produces `WHERE 1 = 1` (or is optimised away by the database). `false()` produces `WHERE 1 != 1`, returning zero rows.

!!! warning "Deny by Default"
    If **no policy** is registered for a `(Model, action)` pair, `authorize_query` appends `WHERE FALSE` automatically — the query returns zero rows. Data is never leaked by a missing policy. Configure `on_missing="raise"` to raise `NoPolicyError` instead of silently returning nothing.

## Custom Registries

By default, all policies share a global `PolicyRegistry`. For test isolation or multi-tenant applications that need separate policy sets, create a dedicated registry and pass it explicitly:

```python
from sqla_authz import policy, authorize_query
from sqla_authz.policy import PolicyRegistry

tenant_registry = PolicyRegistry()

@policy(Post, "read", registry=tenant_registry)
def post_read(actor: User) -> ColumnElement[bool]:
    return Post.org_id == actor.org_id

# Pass the same registry at query time
stmt = authorize_query(
    select(Post),
    actor=current_user,
    action="read",
    registry=tenant_registry,
)
```

Isolation is useful in tests to avoid cross-test pollution:

```python
def test_post_read_policy():
    reg = PolicyRegistry()

    @policy(Post, "read", registry=reg)
    def read(actor):
        return Post.author_id == actor.id

    stmt = authorize_query(select(Post), actor=user, action="read", registry=reg)
    # assert on stmt...
```

## Common Patterns

### Admin Bypass

```python
from sqlalchemy import true

@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    if actor.is_superuser:
        return true()
    return Post.author_id == actor.id
```

### Tenant Scoping

All rows must belong to the actor's organisation:

```python
@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    return Post.org_id == actor.org_id
```

### Visibility Levels

```python
from sqlalchemy import or_

@policy(Document, "read")
def doc_read(actor: User) -> ColumnElement[bool]:
    return or_(
        Document.visibility == "public",
        and_(Document.visibility == "internal", Document.org_id == actor.org_id),
        and_(Document.visibility == "private", Document.owner_id == actor.id),
    )
```

### Role-Gated Write

```python
from sqlalchemy import false

@policy(Post, "delete")
def post_delete(actor: User) -> ColumnElement[bool]:
    if actor.role not in ("admin", "moderator"):
        return false()
    return Post.org_id == actor.org_id
```

!!! tip "Show the SQL"
    To inspect the exact SQL your policy produces, compile the statement after `authorize_query`:

    ```python
    from sqlalchemy.dialects import postgresql

    stmt = authorize_query(select(Post), actor=user, action="read")
    print(stmt.compile(
        dialect=postgresql.dialect(),
        compile_kwargs={"literal_binds": True},
    ))
    ```

    For a dialect-agnostic preview (parameter placeholders instead of values):

    ```python
    print(str(stmt.compile(compile_kwargs={"literal_binds": True})))
    ```
