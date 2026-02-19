# Composable Predicates

## What Are Predicates?

Predicates are reusable authorization building blocks. A `Predicate` wraps a function that takes an actor and returns a `ColumnElement[bool]`, and supports logical composition with `&`, `|`, and `~` operators.

## Creating Predicates

### Using the @predicate decorator

```python
from sqla_authz.policy._predicate import predicate

@predicate
def is_published(actor) -> ColumnElement[bool]:
    return Post.is_published == True

@predicate
def is_author(actor) -> ColumnElement[bool]:
    return Post.author_id == actor.id
```

### Using Predicate directly

```python
from sqla_authz.policy._predicate import Predicate

is_admin = Predicate(
    lambda actor: true() if actor.role == "admin" else false(),
    name="is_admin",
)
```

## Composing Predicates

### OR (|) — Any predicate grants access
```python
can_read = is_published | is_author
# Equivalent to: or_(Post.is_published == True, Post.author_id == actor.id)
```

### AND (&) — Both must be true
```python
can_edit_draft = is_author & ~is_published
# Author AND not published
```

### NOT (~) — Invert a predicate
```python
is_not_archived = ~Predicate(lambda actor: Post.status == "archived", name="archived")
```

## Using Predicates with @policy

```python
from sqla_authz import policy

@policy(Post, "read", predicate=is_published | is_author)
def post_read(actor) -> ColumnElement[bool]:
    ...  # body is ignored when predicate is provided
```

When `predicate=` is set, the predicate's `__call__` is used instead of the function body.

## Built-in Predicates

| Predicate | Returns | Use Case |
|-----------|---------|----------|
| `always_allow` | `true()` | Grant access to everyone |
| `always_deny` | `false()` | Deny access to everyone |

```python
from sqla_authz.policy._predicate import always_allow, always_deny

@policy(PublicResource, "read", predicate=always_allow)
def public_read(actor): ...
```

## Real-World Example

```python
# Define reusable predicates
is_owner = predicate(lambda actor: Document.owner_id == actor.id)
is_team_member = predicate(lambda actor: Document.team_id == actor.team_id)
is_public = predicate(lambda actor: Document.visibility == "public")

# Compose for different actions
@policy(Document, "read", predicate=is_public | is_team_member | is_owner)
def doc_read(actor): ...

@policy(Document, "update", predicate=is_owner | is_team_member)
def doc_update(actor): ...

@policy(Document, "delete", predicate=is_owner)
def doc_delete(actor): ...
```

!!! tip "Naming Predicates"
    Always provide a `name` when using `Predicate()` directly. The `@predicate` decorator uses `__name__` automatically. Names appear in `repr()` and audit logs.

!!! info "Predicates vs Inline Policies"
    Use predicates when you have reusable conditions across multiple policies. For one-off policies, inline `@policy` functions are simpler.
