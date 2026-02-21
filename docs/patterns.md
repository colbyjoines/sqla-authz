# Common Patterns

Practical authorization patterns for common use cases.

## Resource ownership

Allow users to access only their own resources:

```python
from sqla_authz import policy

@policy(Post, "read")
def own_posts(actor):
    return Post.author_id == actor.id

@policy(Post, "update")
def own_posts_update(actor):
    return Post.author_id == actor.id
```

## Public/private content toggle

Allow public content to be read by anyone, private content only by the author:

```python
@policy(Post, "read")
def published_or_own(actor):
    return (Post.is_published == True) | (Post.author_id == actor.id)
```

## Role-based admin bypass

Grant admins full access while restricting other roles:

```python
from sqlalchemy import true

@policy(Post, "read")
def admin_or_published(actor):
    if actor.role == "admin":
        return true()
    return Post.is_published == True
```

## Multi-tenant row isolation

Restrict access to resources within the actor's organization:

```python
@policy(Document, "read")
def same_org(actor):
    return Document.org_id == actor.org_id

@policy(Document, "update")
def same_org_update(actor):
    return Document.org_id == actor.org_id
```

## Combining multiple policies

Multiple policies for the same `(model, action)` are OR'd together.
Any matching policy grants access:

```python
@policy(Post, "read")
def published_posts(actor):
    return Post.is_published == True

@policy(Post, "read")
def own_drafts(actor):
    return (Post.is_published == False) & (Post.author_id == actor.id)
```

## Query-level authorization

Filter query results to only authorized rows:

```python
from sqla_authz import authorize_query

# Sync
stmt = select(Post).order_by(Post.created_at.desc())
stmt = authorize_query(stmt, actor=current_user, action="read")
result = session.execute(stmt)

# Async
stmt = select(Post).order_by(Post.created_at.desc())
stmt = authorize_query(stmt, actor=current_user, action="read")
result = await session.execute(stmt)
```

## Point checks on single instances

Check authorization on a specific resource:

```python
from sqla_authz import can, authorize

# Returns True/False
if can(current_user, "update", post):
    # proceed with update
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
