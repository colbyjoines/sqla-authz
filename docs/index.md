---
title: Home
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

<img src="assets/brand/sqla-authz-icon.svg" alt="sqla-authz" class="hero-icon">

# sqla-authz

Database-enforced authorization policies written in pure Python. For SQLAlchemy 2.0.

<div class="hero-install" markdown>

```bash
pip install sqla-authz
```

[![PyPI version](https://img.shields.io/pypi/v/sqla-authz.svg)](https://pypi.org/project/sqla-authz/)
[![Python versions](https://img.shields.io/pypi/pyversions/sqla-authz.svg)](https://pypi.org/project/sqla-authz/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

</div>

---

## What it does

You define who can see what as a Python function. sqla-authz compiles it into a database-level filter and applies it to your query:

```python
from sqla_authz import READ, authorize_query, policy
from sqlalchemy import ColumnElement, or_, select, true


@policy(Post, READ)
def post_read(actor: User) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()  # admins see all rows
    return or_(Post.is_published == True, Post.author_id == actor.id)


stmt = select(Post).order_by(Post.created_at.desc())
stmt = authorize_query(stmt, actor=current_user, action=READ)
# SQL: SELECT ... FROM post WHERE (is_published = true OR author_id = :id)
```

---

## Why it fits

sqla-authz is a SQLAlchemy-native authorization kernel for Python apps. It is strongest when you want authorization close to the query layer instead of spread across endpoint checks and post-query filtering.

- **Explicit first** — start with `authorize_query()` so authorization stays visible and reviewable.
- **Deny by default** — no policy for a `(model, action)` pair means `WHERE FALSE`, not a silent data leak.
- **Scopes for boundaries** — tenant or org-wide restrictions are AND'd across matching policies.
- **Point checks for instances** — use `can()`, `authorize()`, and `authorize_create()` for object-specific decisions.
- **Optional automation** — move to `authorized_sessionmaker()` or FastAPI `AuthzDep` once the explicit path is stable.
- **No DSL or sidecar** — policies stay in Python and return normal SQLAlchemy expressions.

---

- [Getting Started](getting-started.md) — Installation, first policy, core concepts
- [Limitations](limitations.md) — Known boundaries and project status
- [API Reference](reference/api.md) — All public functions, classes, and types
