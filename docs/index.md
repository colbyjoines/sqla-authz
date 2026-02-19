---
title: Home
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

<img src="assets/brand/sqla-authz-icon.svg" alt="sqla-authz" class="hero-icon">

# Authorization that compiles to SQL

Define policies in Python. Get SQL WHERE clauses automatically.
No external servers, no custom DSLs.

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

## See it in action

```python title="Authorization in ten lines"
from sqla_authz import policy, authorize_query
from sqlalchemy import ColumnElement, or_, select


@policy(Post, "read")
def post_read(actor) -> ColumnElement[bool]:
    return or_(Post.is_published == True, Post.author_id == actor.id)


stmt = select(Post).order_by(Post.created_at.desc())
stmt = authorize_query(stmt, actor=current_user, action="read")
# SQL: SELECT ... FROM post WHERE (is_published = true OR author_id = :id)
```

One decorator. One call. Your policy becomes a WHERE clause — evaluated by the database, not in Python.

---

## Why sqla-authz?

| Feature | sqla-authz | sqlalchemy-oso | PyCasbin | Cerbos |
|---------|:----------:|:--------------:|:--------:|:------:|
| SQL WHERE clause generation | Yes | Yes *(deprecated)* | No | Yes *(via server)* |
| SQLAlchemy 2.0 (`select()`) | Yes | No | N/A | Yes |
| `AsyncSession` support | Yes | No | N/A | No |
| Embedded (no server) | Yes | Yes | Yes | No |
| Python-native policies | Yes | No — Polar DSL | No — `.conf` files | No — YAML |
| Type-safe (pyright strict) | Yes | No | No | No |

---

## How it works

```mermaid
flowchart LR
    A["@policy(Post, 'read')<br/>Python function"]
    B[PolicyRegistry]
    C{Entry Point}
    D["authorize_query()"]
    E["do_orm_execute<br/>event hook"]
    F["AuthzDep<br/>(FastAPI)"]
    G[Policy Compiler]
    H["ColumnElement[bool]<br/>SA filter expression"]
    I["stmt.where(filter)"]
    J["session.execute()<br/>(sync or async)"]

    A --> B
    B --> C
    C -->|Explicit| D
    C -->|Automatic| E
    C -->|Framework| F
    D --> G
    E --> G
    F --> G
    G --> H
    H --> I
    I --> J
```

Policies are registered in a central `PolicyRegistry`. Whichever entry point you use — explicit `authorize_query()`, the automatic `do_orm_execute` hook, or a framework integration — the same compiler converts your Python function into a `ColumnElement[bool]` and appends it as a `WHERE` clause.

---

## Key features

<div class="grid cards" markdown>

-   **SQL-Native**

    ---

    Policies compile to real SQL `WHERE` clauses. Filtering happens in the database — not in Python loops after fetching rows. Works with every database SQLAlchemy supports.

-   **Async-Equal**

    ---

    The same policy functions work unchanged with both sync `Session` and `AsyncSession`. Filter construction is pure Python — no I/O, no `await`. The async boundary stays at `session.execute()`.

-   **Fail-Closed**

    ---

    No registered policy for a `(model, action)` pair? The query gets `WHERE FALSE` appended — zero rows returned. Missing policies never leak data. Configurable to raise `NoPolicyError` instead.

-   **Zero Dependencies**

    ---

    Ships with no runtime dependencies beyond SQLAlchemy itself. No external authorization server. No network round-trip. No sidecar container. Just a library.

-   **Type-Safe**

    ---

    Written for pyright strict mode. Policies are typed Python functions. No stringly-typed rule files. Your IDE understands your policies; refactoring just works.

-   **Composable**

    ---

    Multiple policies for the same `(model, action)` are OR'd together automatically. Build complex rules from small, testable pieces using `&`, `|`, and `~` operators.

</div>

---

## Quick links

<div class="grid cards" markdown>

-   :material-rocket-launch: **Getting Started**

    ---

    Install sqla-authz, write your first policy, and run an authorized query in under five minutes.

    [Get started](getting-started/quickstart.md)

-   :material-lightning-bolt: **FastAPI Guide**

    ---

    Add per-route authorization with `AuthzDep`. Handles actor extraction, error responses, and async sessions.

    [FastAPI integration](integrations/fastapi.md)

-   :material-swap-horizontal: **Migration from Oso**

    ---

    Moving from `sqlalchemy-oso`? Learn how to translate Polar rules to `@policy` functions.

    [Migration guide](migration/from-oso.md)

-   :material-book-open-variant: **API Reference**

    ---

    Complete reference for `policy`, `authorize_query`, `can`, `authorize`, `configure`, and all public types.

    [API reference](reference/api.md)

</div>
