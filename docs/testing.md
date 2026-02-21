# Testing

```bash
pip install sqla-authz[testing]
```

sqla-authz policies are Python functions that return SQLAlchemy expressions, so they're straightforward to test — create an actor, run a query, check the results.

## Mock Actors

Lightweight actors for testing without needing real user records in the database:

```python
from sqla_authz.testing import MockActor, make_admin, make_user, make_anonymous

admin = make_admin()                                  # id=1, role="admin"
user = make_user(id=7, role="editor", org_id=5)       # custom attributes
anon = make_anonymous()                               # id=0, role="anonymous"
```

`MockActor` accepts arbitrary keyword arguments as attributes, so your policies can reference `actor.team_id`, `actor.org_id`, or any other field you need.

## Assertion Helpers

Test authorization outcomes without writing boilerplate query-and-check code:

```python
from sqla_authz.testing import assert_authorized, assert_denied, assert_query_contains

# Verify that a query returns rows for this actor
assert_authorized(session, select(Post), actor=make_admin(), action="read",
                  expected_count=3, registry=authz_registry)

# Verify that a query returns zero rows
assert_denied(session, select(Post), actor=make_anonymous(), action="read",
              registry=authz_registry)

# Check the compiled SQL without executing it (no database needed)
assert_query_contains(select(Post), actor=make_user(id=42), action="read",
                      text="author_id = 42", registry=authz_registry)
```

## Pytest Fixtures

Fixtures are auto-discovered via the `pytest11` entry point — no imports or `conftest.py` registration needed.

- **`authz_registry`** — Fresh, empty `PolicyRegistry` for each test. Prevents policies registered at module level from leaking between tests.
- **`authz_config`** — Returns the default `AuthzConfig`.

```python
def test_members_see_own_posts(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def own_posts(actor: User) -> ColumnElement[bool]:
        return Post.author_id == actor.id

    assert_authorized(session, select(Post), actor=make_user(id=1),
                      action="read", registry=authz_registry)
    assert_denied(session, select(Post), actor=make_user(id=999),
                  action="read", registry=authz_registry)
```

!!! tip "Registry Isolation"
    Always use a per-test `PolicyRegistry` (the `authz_registry` fixture or a local instance). Module-level `@policy` decorators register to the global registry, which persists across tests and causes test pollution.
