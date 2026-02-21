# Common Patterns

Practical authorization patterns for common use cases.

---

## Role-Based Access Control (RBAC)

RBAC assigns permissions based on an actor's role. sqla-authz makes this natural:
the `actor.role` check happens in Python, and the resulting filter runs in SQL.

### Hierarchical roles

Map a role hierarchy to progressively wider filters. Multiple actions
get distinct policies — each returns the right filter for that role level:

```python
from sqlalchemy import ColumnElement, or_, true, false
from sqla_authz import policy

ROLE_RANK = {"viewer": 0, "editor": 1, "manager": 2, "admin": 3}

@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    rank = ROLE_RANK.get(actor.role, 0)
    if rank >= ROLE_RANK["admin"]:
        return true()
    if rank >= ROLE_RANK["editor"]:
        return or_(Post.is_published == True, Post.author_id == actor.id)
    return Post.is_published == True

@policy(Post, "update")
def post_update(actor: User) -> ColumnElement[bool]:
    rank = ROLE_RANK.get(actor.role, 0)
    if rank >= ROLE_RANK["admin"]:
        return true()
    if rank >= ROLE_RANK["editor"]:
        return Post.author_id == actor.id
    return false()  # viewers cannot update

@policy(Post, "delete")
def post_delete(actor: User) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()
    return false()
```

### Multi-tenant with role scoping

Combine role checks with organization isolation — a common SaaS pattern:

```python
@policy(Document, "read")
def org_scoped_read(actor: User) -> ColumnElement[bool]:
    if actor.role == "super_admin":
        return true()
    return Document.org_id == actor.org_id

@policy(Document, "update")
def org_scoped_update(actor: User) -> ColumnElement[bool]:
    if actor.role in ("admin", "super_admin"):
        return Document.org_id == actor.org_id
    if actor.role == "editor":
        return (Document.org_id == actor.org_id) & (Document.owner_id == actor.id)
    return false()
```

---

## Attribute-Based Access Control (ABAC)

ABAC makes decisions based on attributes of the actor, the resource, or the
environment. Because policies are plain Python that return SQL expressions,
you can mix Python-side attribute checks with SQL-side column filters freely.

### Sensitivity levels

Restrict access based on a document's classification vs. the actor's clearance:

```python
from sqlalchemy import ColumnElement, true
from sqla_authz import policy

CLEARANCE = {"public": 0, "internal": 1, "confidential": 2, "secret": 3}

@policy(Document, "read")
def clearance_check(actor: User) -> ColumnElement[bool]:
    level = CLEARANCE.get(actor.clearance, 0)
    if level >= CLEARANCE["secret"]:
        return true()
    if level >= CLEARANCE["confidential"]:
        return Document.classification.in_(["public", "internal", "confidential"])
    if level >= CLEARANCE["internal"]:
        return Document.classification.in_(["public", "internal"])
    return Document.classification == "public"
```

### Status workflow with time gating

Combine content status, actor relationship, and time-based embargo in one policy:

```python
from datetime import datetime, timezone
from sqlalchemy import ColumnElement, or_, true

@policy(Article, "read")
def workflow_visibility(actor: User) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()
    now = datetime.now(timezone.utc)
    return or_(
        Article.status == "published",
        (Article.status == "review") & (Article.reviewer_id == actor.id),
        (Article.status == "draft") & (Article.author_id == actor.id),
    ) & or_(
        Article.embargo_date.is_(None),
        Article.embargo_date <= now,
    )
```

---

## Composable predicates

Extract repeated conditions into reusable predicates with `&`, `|`, `~`:

```python
from sqla_authz.policy import predicate

@predicate
def is_published(actor: User) -> ColumnElement[bool]:
    return Post.is_published == True

@predicate
def is_author(actor: User) -> ColumnElement[bool]:
    return Post.author_id == actor.id

@predicate
def is_same_org(actor: User) -> ColumnElement[bool]:
    return Post.author.has(User.org_id == actor.org_id)

# Compose with operators
public_or_own = is_published | is_author
own_in_org    = is_author & is_same_org

@policy(Post, "read", predicate=public_or_own)
def post_read(actor: User) -> ColumnElement[bool]: ...

@policy(Post, "update", predicate=own_in_org)
def post_update(actor: User) -> ColumnElement[bool]: ...
```

---

## Query-level authorization

Filter query results to only authorized rows:

```python
from sqla_authz import authorize_query

# Sync
stmt = select(Post).order_by(Post.created_at.desc())
stmt = authorize_query(stmt, actor=current_user, action="read")
result = session.execute(stmt)

# Async — same code, just await
stmt = select(Post).order_by(Post.created_at.desc())
stmt = authorize_query(stmt, actor=current_user, action="read")
result = await session.execute(stmt)
```

## Point checks on single instances

Check authorization on a specific resource without a database round-trip:

```python
from sqla_authz import can, authorize

# Returns True/False
if can(current_user, "update", post):
    ...

# Raises AuthorizationDenied if denied
authorize(current_user, "delete", post)
```

## Safe primary key lookups

Fetch by PK with built-in authorization:

```python
from sqla_authz import safe_get, safe_get_or_raise

# Returns None if not found or denied
post = safe_get(session, Post, post_id, actor=current_user)

# Raises AuthorizationDenied if denied, None if not found
post = safe_get_or_raise(session, Post, post_id, actor=current_user)
```

Async variants:

```python
from sqla_authz import async_safe_get, async_safe_get_or_raise

post = await async_safe_get(session, Post, post_id, actor=current_user)
post = await async_safe_get_or_raise(session, Post, post_id, actor=current_user)
```

## Debugging with explain

Understand why access was granted or denied:

```python
from sqla_authz import explain_access

explanation = explain_access(current_user, "read", post)
print(explanation)
# AccessExplanation(allowed=True, policies=[...])
```

> **Note:** `explain_access()` is for development only. See
> [Limitations](limitations.md) for details.
