# Testing

```bash
pip install sqla-authz[testing]
```

## Mock Actors

```python
from sqla_authz.testing import MockActor, make_admin, make_user, make_anonymous

admin = make_admin()          # id=1, role="admin"
user  = make_user(id=7, role="editor", org_id=5)
anon  = make_anonymous()      # id=0, role="anonymous"
```

## Assertion Helpers

```python
from sqla_authz.testing import assert_authorized, assert_denied, assert_query_contains

# Asserts at least one row returned after authorization
assert_authorized(session, select(Post), actor=make_admin(), action="read",
                  expected_count=3, registry=authz_registry)

# Asserts zero rows returned
assert_denied(session, select(Post), actor=make_anonymous(), action="read",
              registry=authz_registry)

# Checks compiled SQL contains a substring (no database required)
assert_query_contains(select(Post), actor=make_user(id=42), action="read",
                      text="author_id = 42", registry=authz_registry)
```

## Pytest Fixtures

Fixtures are auto-discovered via the `pytest11` entry point — no imports needed.

- **`authz_registry`** — Fresh, empty `PolicyRegistry` per test. Isolates policies from the global registry and other tests.
- **`authz_config`** — Returns the default `AuthzConfig`.

```python
def test_custom_policy(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def allow_published(actor) -> ColumnElement[bool]:
        return Post.is_published == True

    assert_authorized(session, select(Post), actor=make_user(),
                      action="read", registry=authz_registry)
```

!!! tip "Registry Isolation"
    Always use a local `PolicyRegistry` or the `authz_registry` fixture to prevent test pollution from module-level `@policy` decorators.
