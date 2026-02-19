# Migrating from Oso

This guide helps teams migrate from the deprecated `sqlalchemy-oso` library (deprecated December 2023) to `sqla-authz`.

## Key Differences

| Aspect | sqlalchemy-oso | sqla-authz |
|---|---|---|
| Policy language | Polar DSL (`.polar` files) | Python functions |
| SQLAlchemy support | Legacy `Query` API | SA 2.0 `select()` |
| Async support | No | Full (`AsyncSession`) |
| Architecture | Rust FFI + Polar VM | Pure Python |
| Primary API | `authorized_sessionmaker` (automatic) | `authorize_query()` (explicit) |
| Dependencies | `oso` + `sqlalchemy-oso` | `sqla-authz` only |
| Default behavior | Varies | Deny by default (`WHERE FALSE`) |
| Type safety | No | pyright strict |

---

## Policy Conversion

### Basic Allow Rules

**Before (Polar):**

```polar
allow(actor: User, "read", post: Post) if
    post.is_published = true;

allow(actor: User, "read", post: Post) if
    post.owner_id = actor.id;
```

**After (Python):**

```python
from sqlalchemy import or_, true
from sqla_authz import policy

@policy(Post, "read")
def read_post(actor: User, Post: type) -> ColumnElement[bool]:
    return or_(
        Post.is_published == true(),
        Post.owner_id == actor.id,
    )
```

Multiple `allow` clauses in Polar become `or_()` branches in a single `@policy` function. Alternatively, register multiple `@policy` functions for the same `(model, action)` pair — they are OR'd together automatically.

---

### Role-Based Rules

**Before (Polar):**

```polar
allow(actor: User, "edit", post: Post) if
    actor.role = "admin";

allow(actor: User, "edit", post: Post) if
    post.owner_id = actor.id;
```

**After (Python):**

```python
from sqlalchemy import true, false
from sqla_authz import policy

@policy(Post, "edit")
def edit_post(actor: User, Post: type) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()  # admin sees everything
    return Post.owner_id == actor.id
```

Python branching replaces Polar's multi-rule dispatch. Use `sqlalchemy.true()` and `sqlalchemy.false()` as unconditional SQL literals.

---

### Relationship Rules

**Before (Polar):**

```polar
allow(actor: User, "read", comment: Comment) if
    post matches Post and
    comment.post = post and
    post.owner_id = actor.id;
```

**After (Python):**

```python
from sqla_authz import policy

@policy(Comment, "read")
def read_comment(actor: User, Comment: type) -> ColumnElement[bool]:
    return Comment.post.has(Post.owner_id == actor.id)
```

Polar's relationship traversal maps to SQLAlchemy's `.has()` (many-to-one) and `.any()` (one-to-many). The compiler selects the correct method automatically via `sqlalchemy.inspect()` when using `authorize_query()`.

---

## API Mapping

### `authorize_model()` → `authorize_query()`

**Before:**

```python
from sqlalchemy_oso import authorized_sessionmaker

AuthorizedSession = authorized_sessionmaker(
    bind=engine,
    get_oso=lambda: oso,
    get_user=lambda: current_user,
    get_action=lambda: "read",
)

with AuthorizedSession() as session:
    posts = session.query(Post).all()
```

**After:**

```python
from sqla_authz import authorize_query
from sqlalchemy import select

with Session(engine) as session:
    stmt = authorize_query(select(Post), actor=current_user, action="read")
    posts = session.scalars(stmt).all()
```

`authorize_query()` is a pure function that returns a modified `Select` statement. No session subclass required.

---

### `authorized_sessionmaker` → `sqla_authz.authorized_sessionmaker` or explicit

If you prefer automatic interception (the closest equivalent to the Oso approach), `sqla-authz` provides an opt-in session wrapper:

```python
from sqla_authz.session import authorized_sessionmaker

AutoSession = authorized_sessionmaker(
    bind=engine,
    actor_fn=lambda: current_user,
    action="read",
)

with AutoSession() as session:
    posts = session.scalars(select(Post)).all()  # automatically filtered
```

Automatic interception uses the `do_orm_execute` event hook. It is opt-in — standard `Session` objects are never modified.

---

### Oso instance setup → no setup

**Before:**

```python
from oso import Oso
from sqlalchemy_oso import register_models

oso = Oso()
register_models(oso, Base)
oso.load_files(["policy.polar"])
```

**After:**

```python
# Nothing. Policies register themselves on import.
import myapp.policies  # importing the module is sufficient
```

`@policy`-decorated functions register with the global `PolicyRegistry` at import time. No Oso instance, no file loading, no `register_models()`.

---

## Migration Checklist

1. **Install sqla-authz**

    ```bash
    pip install sqla-authz
    # or
    uv add sqla-authz
    ```

2. **Convert Polar files to Python policies** — Create one `policies.py` module per domain area. Translate each `allow` rule to a `@policy`-decorated function. Use `or_()` for multiple branches, `true()`/`false()` for unconditional results, `.has()`/`.any()` for relationships.

3. **Migrate to SA 2.0 style** — Replace `session.query(Model)` with `select(Model)`. Replace `.filter()` with `.where()`. Replace `.first()` with `session.scalars(stmt).first()`.

4. **Replace Oso API calls** — Replace `oso.authorize()` / `authorized_session.query()` with `authorize_query(select(Model), actor=actor, action=action)`.

5. **Update imports** — Remove all `from oso import ...` and `from sqlalchemy_oso import ...`. Add `from sqla_authz import policy, authorize_query`.

6. **Remove old dependencies** — Uninstall `oso` and `sqlalchemy-oso`:

    ```bash
    pip uninstall oso sqlalchemy-oso
    # or remove from pyproject.toml / requirements.txt
    ```

7. **Run test suite** — Verify that previously permitted queries still return rows and that previously denied queries return zero rows (or raise `AuthorizationDenied` if configured).

---

## Common Patterns

### Admin Bypass

**Before (Polar):**

```polar
allow(actor: User, _action, _resource) if
    actor.role = "admin";
```

**After (Python):**

```python
from sqlalchemy import true
from sqla_authz import policy

@policy(Post, "read")
def admin_read_post(actor: User, Post: type) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()
    return Post.is_published == true()
```

Because multiple `@policy` functions for the same `(model, action)` are OR'd, you can also split the admin bypass into a separate function:

```python
@policy(Post, "read")
def admin_bypass(actor: User, Post: type) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()
    return false()

@policy(Post, "read")
def published_posts(actor: User, Post: type) -> ColumnElement[bool]:
    return Post.is_published == true()
```

---

### Multi-Tenancy

**Before (Polar):**

```polar
allow(actor: User, "read", resource) if
    resource.organization_id = actor.organization_id;
```

**After (Python):**

```python
from sqla_authz import policy

@policy(Document, "read")
def tenant_read(actor: User, Document: type) -> ColumnElement[bool]:
    return Document.organization_id == actor.organization_id
```

The Python version is identical in intent but produces a typed, IDE-navigable, refactor-safe expression.

---

### Field-Based Visibility

Oso's field-level authorization required separate rules per field. `sqla-authz` expresses the same logic through action namespacing:

**Before (Polar):**

```polar
allow_field(actor: User, "read", post: Post, "content") if
    post.is_published = true;

allow_field(actor: User, "read", post: Post, "draft_notes") if
    post.owner_id = actor.id;
```

**After (Python):**

```python
@policy(Post, "read")
def read_post(actor: User, Post: type) -> ColumnElement[bool]:
    return Post.is_published == true()

@policy(Post, "read:draft_notes")
def read_draft_notes(actor: User, Post: type) -> ColumnElement[bool]:
    return Post.owner_id == actor.id
```

Use compound action strings (`"read:draft_notes"`) to scope policies to specific fields or sub-resources. The action string is arbitrary — define whatever granularity your domain requires.
