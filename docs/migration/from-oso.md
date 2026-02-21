# Migrating from Oso to sqla-authz

Oso (the in-process authorization library with Polar DSL) was deprecated in December 2023. This guide helps you migrate from Oso's Polar-based rules to sqla-authz's Python-native `@policy` decorators.

---

## Concept Mapping

| Oso / Polar | sqla-authz | Notes |
|---|---|---|
| `.polar` file | Python module with `@policy` decorators | Policies are Python code, not a separate DSL |
| `allow(actor, action, resource)` | `@policy(Model, "action")` | Decorator-based registration |
| `oso.authorize(actor, action, resource)` | `authorize(actor, action, resource)` | Raises `AuthorizationDenied` on failure |
| `oso.is_allowed(actor, action, resource)` | `can(actor, action, resource)` | Returns `bool` |
| `OsoError` | `AuthzError` | Base exception class |
| `oso.authorize_request(actor, request)` | FastAPI `Depends(get_authorized_session)` | Framework integration |
| `Oso.register_class(Model)` | Automatic via `@policy(Model, ...)` | No manual registration needed |
| `actor.role = "admin"` (Polar) | `actor.role == "admin"` (Python) | Standard Python comparison |
| `resource.author = actor` (Polar) | `Model.author_id == actor.id` (SQL expression) | SQLAlchemy column expressions |
| Polar `and` / `,` | `and_()` or `&` | SQLAlchemy operators |
| Polar `or` | `or_()` or `\|` | SQLAlchemy operators |
| Polar `not` | `~` or `not_()` | SQLAlchemy operators |
| `authorize_filter(actor, action, Post)` | `authorize_query(select(Post), actor=..., action=...)` | Query-level filtering |
| Polar inline queries | Not needed | Policies return SQL expressions directly |
| `oso.load_files(["policy.polar"])` | Import module with `@policy` decorators | Python import system |

---

## Side-by-Side Code Translations

### Pattern 1: Simple Field Comparison

**Oso (Polar):**

```polar
# policy.polar
allow(actor: User, "read", post: Post) if
    post.is_published = true;
```

**sqla-authz (Python):**

```python
# policies.py
from sqlalchemy import ColumnElement
from sqla_authz import policy
from myapp.models import Post, User

@policy(Post, "read")
def post_read_published(actor: User) -> ColumnElement[bool]:
    return Post.is_published == True
```

### Pattern 2: Actor-Based Access (Own Resources)

**Oso (Polar):**

```polar
allow(actor: User, "read", post: Post) if
    post.is_published = true;

allow(actor: User, "read", post: Post) if
    post.author = actor;

allow(actor: User, "update", post: Post) if
    post.author = actor;
```

**sqla-authz (Python):**

```python
from sqlalchemy import ColumnElement
from sqla_authz import policy
from myapp.models import Post, User

@policy(Post, "read")
def post_read_published(actor: User) -> ColumnElement[bool]:
    return Post.is_published == True

@policy(Post, "read")
def post_read_own(actor: User) -> ColumnElement[bool]:
    return Post.author_id == actor.id

@policy(Post, "update")
def post_update_own(actor: User) -> ColumnElement[bool]:
    return Post.author_id == actor.id
```

Multiple `@policy` decorators for the same `(Model, action)` are automatically OR'd together, matching Oso's behavior of multiple `allow` rules.

### Pattern 3: Role-Based Access

**Oso (Polar):**

```polar
allow(actor: User, "read", _post: Post) if
    actor.role = "admin";

allow(actor: User, "read", post: Post) if
    actor.role = "editor" and
    post.is_published = true;

allow(actor: User, "delete", _post: Post) if
    actor.role = "admin";
```

**sqla-authz (Python):**

```python
from sqlalchemy import ColumnElement, true, false
from sqla_authz import policy
from myapp.models import Post, User

@policy(Post, "read")
def admin_reads_all(actor: User) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()
    return false()

@policy(Post, "read")
def editor_reads_published(actor: User) -> ColumnElement[bool]:
    if actor.role == "editor":
        return Post.is_published == True
    return false()

@policy(Post, "delete")
def admin_deletes(actor: User) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()
    return false()
```

Key difference: Role checks happen in Python (against the actor object), while resource conditions become SQL expressions. Use `true()` to grant unconditional access and `false()` to deny.

### Pattern 4: Relationship Traversal

**Oso (Polar):**

```polar
allow(actor: User, "read", post: Post) if
    post.author.org_id = actor.org_id;
```

**sqla-authz (Python):**

```python
from sqlalchemy import ColumnElement
from sqla_authz import policy
from myapp.models import Post, User

@policy(Post, "read")
def same_org_posts(actor: User) -> ColumnElement[bool]:
    return Post.author.has(User.org_id == actor.org_id)
```

SQLAlchemy's `.has()` (for many-to-one) and `.any()` (for one-to-many) replace Polar's dot-notation relationship traversal. These generate SQL `EXISTS` subqueries.

---

## Step-by-Step Migration Checklist

### 1. Inventory Your Polar Rules

List all `.polar` files and categorize each `allow` rule by:

- **Model** (the resource type)
- **Action** (read, update, delete, etc.)
- **Condition type** (field check, role check, relationship, etc.)

### 2. Set Up sqla-authz

```bash
pip install sqla-authz
```

```python
# app/auth.py
from sqla_authz import configure
from sqla_authz.session import install_interceptor

configure(on_missing_policy="raise")  # Fail loudly during migration

# Install on your session factory
install_interceptor(
    SessionLocal,
    actor_provider=get_current_user,
    action="read",
)
```

Setting `on_missing_policy="raise"` ensures you catch any models that haven't been migrated yet.

### 3. Convert Rules to `@policy` Decorators

For each `allow` rule in your `.polar` files, create a corresponding `@policy` function:

1. **Simple field comparisons** (`resource.field = value`) become `Model.field == value`
2. **Actor field checks** (`actor.role = "admin"`) become Python `if` blocks returning `true()` or `false()`
3. **Relationship traversals** (`resource.rel.field`) become `.has()` / `.any()` expressions
4. **Multiple `allow` rules** for the same `(model, action)` become multiple `@policy` decorators (auto-OR'd)
5. **AND conditions** (comma-separated in Polar) become `and_()` or `&` in SQLAlchemy

### 4. Replace Oso API Calls

| Replace this (Oso) | With this (sqla-authz) |
|---|---|
| `oso.is_allowed(actor, "read", post)` | `can(actor, "read", post)` |
| `oso.authorize(actor, "update", post)` | `authorize(actor, "update", post)` |
| `authorized_filter = oso.authorized_query(actor, "read", Post)` | `stmt = authorize_query(select(Post), actor=actor, action="read")` |
| `oso.load_files(["policy.polar"])` | Import your policy module |

### 5. Remove Oso Dependencies

```bash
pip uninstall oso
```

Delete all `.polar` files (keep backups until migration is verified).

### 6. Verify with Tests

Use sqla-authz's testing utilities to verify your migrated policies:

```python
from sqla_authz.testing import MockActor, assert_authorized, assert_denied, policy_matrix

def test_migration_coverage(registry):
    """Ensure all model/action pairs have policies."""
    matrix = policy_matrix(registry, actions=["read", "update", "delete"])
    assert len(matrix.uncovered) == 0, f"Missing policies: {matrix.uncovered}"

def test_admin_reads_all(session, sample_data):
    admin = MockActor(id=1, role="admin")
    assert_authorized(session, select(Post), admin, "read")

def test_viewer_reads_published_only(session, sample_data):
    viewer = MockActor(id=99, role="viewer")
    assert_authorized(session, select(Post), viewer, "read", expected_count=2)
```

### 7. Switch to Production Mode

Once all tests pass, optionally relax the missing policy behavior:

```python
configure(on_missing_policy="deny")  # Deny-by-default (silent)
```

---

## Known Limitations vs Oso

| Capability | Oso | sqla-authz | Notes |
|---|---|---|---|
| Custom DSL | Polar (Turing-complete) | Python + SQLAlchemy | Python IS the DSL; no separate language to learn |
| Graph-based auth (Zanzibar) | oso-cloud (separate product) | Not supported | Use SpiceDB/AuthZed for graph-based authorization |
| `deny` rules | `deny(actor, action, resource)` | Not built-in | Use `false()` in policy functions; or use AND composition |
| Rule priority | Implicit (deny > allow) | OR composition (default) | Multiple policies are OR'd; use conditional logic for priority |
| Recursive rules | Supported in Polar | Not supported | Flatten recursive logic into SQL-compatible expressions |
| Custom Polar types | `type` declarations in Polar | Standard Python classes | Use dataclasses or SQLAlchemy models |
| Built-in RBAC | `resource.has_role(actor)` | Manual role checks | Check `actor.role` in policy functions |
| Policy debugging | `oso.query_rule_once()` | `explain_access()`, `simulate_query()` | Built-in explain and simulation tools |
| Data filtering | `authorized_query()` | `authorize_query()` + session interceptor | Automatic via session interceptor; manual via `authorize_query()` |
| Multi-language | Python, Ruby, Node.js, Go, Rust, Java | Python only | sqla-authz is Python + SQLAlchemy specific |

### What sqla-authz Does Better

- **No separate DSL to learn** -- policies are standard Python with full IDE support (autocomplete, type checking, debugging)
- **SQL-native filtering** -- policies generate efficient SQL WHERE clauses, not in-memory filtering
- **Automatic session interception** -- no need to manually call `authorized_query()` on every query
- **Zero external dependencies** -- no embedded Polar VM, no network calls
- **Testing utilities** -- built-in `MockActor`, assertions, coverage matrix, SQL simulation
- **Type safety** -- full type checking with Pyright/mypy via `ColumnElement[bool]` return types
