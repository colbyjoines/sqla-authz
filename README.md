<div align="center">
  <a href="https://github.com/colbyjoines/sqla-authz">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/sqla-authz-logo-dark.svg">
      <source media="(prefers-color-scheme: light)" srcset="docs/assets/brand/sqla-authz-logo-light.svg">
      <img src="docs/assets/brand/sqla-authz-logo-light.svg" alt="sqla-authz logo" width="360">
    </picture>
  </a>
  <p>
    An intuitive API to write policies in pure Python.<br />
    Embedded row-level authorization for SQLAlchemy 2.0.
  </p>
  <a href="https://colbyjoines.github.io/sqla-authz/"><strong>Explore the docs &raquo;</strong></a>
</div>

---

## Why sqla-authz?

Most authorization libraries answer a yes/no question: *can this user do this action?* That works for protecting endpoints, but not when you need to **filter a query** — *show me only the rows this user is allowed to see.*

sqla-authz generates SQL WHERE clauses from your policies, so the database does the filtering. No post-query Python loops, no N+1 permission checks.

* **SQL-native** — policies compile to `ColumnElement[bool]` WHERE clauses; the database does the filtering
* **Pure Python** — no DSL, no config files; full IDE autocomplete, type checking, and debugging
* **Fail-closed** — missing policy = zero rows, not a data leak
* **Async-equal** — same synchronous policy code works with both `Session` and `AsyncSession`
* **Type-safe** — passes Pyright strict mode with zero errors

## Usage

### Define a Policy

Policies are plain Python functions decorated with `@policy`. They receive an actor and return a SQLAlchemy filter expression:

```python
from sqlalchemy import ColumnElement, or_, true
from sqla_authz import policy, READ

@policy(Post, READ)
def post_read_policy(actor: User) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()
    return or_(Post.is_published == True, Post.author_id == actor.id)
```

### Apply to Queries

Use `authorize_query()` to apply the policy as a WHERE clause:

```python
from sqlalchemy import select
from sqla_authz import authorize_query, READ

stmt = select(Post).order_by(Post.created_at.desc())
stmt = authorize_query(stmt, actor=current_user, action=READ)
result = session.execute(stmt)
# -> SELECT ... FROM post WHERE (is_published = true OR author_id = :id)
```

No policy registered for a model? The query returns **zero rows** — authorization is deny-by-default.

### Scopes

Scopes are cross-cutting filters (like tenant isolation) that are AND'd with all policies — define them once instead of repeating in every policy:

```python
from sqla_authz import scope

@scope(applies_to=[Post, Comment, Document])
def tenant(actor: User, Model: type) -> ColumnElement[bool]:
    return Model.org_id == actor.org_id
```

Composition: `final_filter = (policy_1 OR policy_2) AND scope_1 AND scope_2`. Use `verify_scopes(Base, field="org_id")` at startup to catch models missing a scope.

### Point Checks

Check a single resource without hitting the database:

```python
from sqla_authz import can, authorize

if can(current_user, "read", some_post):
    ...

# Or raise AuthorizationDenied if denied
authorize(current_user, "read", some_post)
```

### Automatic Session Interception

Opt-in to authorize every SELECT automatically:

```python
from sqla_authz.session import authorized_sessionmaker

Session = authorized_sessionmaker(
    bind=engine,
    actor_provider=get_current_user,
    action="read",
)
```

### FastAPI Integration

Inject authorized query results directly into your endpoints:

```python
from sqla_authz.integrations.fastapi import AuthzDep, get_actor, get_session, install_error_handlers

app.dependency_overrides[get_actor] = get_current_user
app.dependency_overrides[get_session] = get_db
install_error_handlers(app)  # maps AuthorizationDenied → 403, NoPolicyError → 500

@app.get("/posts")
async def list_posts(posts: list[Post] = AuthzDep(Post, "read")):
    return posts

@app.get("/posts/{post_id}")
async def get_post(post: Post = AuthzDep(Post, "read", id_param="post_id")):
    return post
```

_For more examples and advanced patterns, see the [Documentation](https://colbyjoines.github.io/sqla-authz/)._

## Getting Started

```sh
pip install sqla-authz
```

For development:

```sh
git clone https://github.com/colbyjoines/sqla-authz.git
cd sqla-authz
uv sync --dev
```

## Architecture

- **Explicit by default** — `authorize_query()` is visible and greppable. Automatic session interception is opt-in.
- **SQL-native** — policies compile to `ColumnElement[bool]`. The database does the filtering, not Python.
- **Async-equal** — same code for `Session` and `AsyncSession`. Filter construction is pure Python with no I/O.
- **Fail-closed** — missing policy = zero rows, not a data leak.

## References

**Colby Joines** - [colby.j.joines@gmail.com](mailto:colby.j.joines@gmail.com)

**Project Repo:** [https://github.com/colbyjoines/sqla-authz](https://github.com/colbyjoines/sqla-authz)

**Project Docs:** [https://colbyjoines.github.io/sqla-authz/](https://colbyjoines.github.io/sqla-authz/)

## Acknowledgments

* [Oso / sqlalchemy-oso](https://github.com/osohq/oso) — the original inspiration; deprecated Dec 2023
* [SQLAlchemy](https://www.sqlalchemy.org/) — the foundation this library builds on
* [Best-README-Template](https://github.com/othneildrew/Best-README-Template) — this README's structure
