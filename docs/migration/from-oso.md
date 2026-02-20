# Migrating from Oso

Moving from the deprecated `sqlalchemy-oso` (December 2023) to `sqla-authz`.

## Key Differences

| Aspect | sqlalchemy-oso | sqla-authz |
|---|---|---|
| Policy language | Polar DSL (`.polar` files) | Python functions |
| SQLAlchemy support | Legacy `Query` API | SA 2.0 `select()` |
| Async support | No | Full (`AsyncSession`) |
| Architecture | Rust FFI + Polar VM | Pure Python |
| Primary API | `authorized_sessionmaker` (automatic) | `authorize_query()` (explicit) |
| Default behavior | Varies | Deny by default (`WHERE FALSE`) |

---

## Policy Conversion

### Basic Rules

=== "Before (Polar)"

    ```polar
    allow(actor: User, "read", post: Post) if
        post.is_published = true;

    allow(actor: User, "read", post: Post) if
        post.owner_id = actor.id;
    ```

=== "After (Python)"

    ```python
    @policy(Post, "read")
    def read_post(actor: User) -> ColumnElement[bool]:
        return or_(Post.is_published == True, Post.owner_id == actor.id)
    ```

Multiple `allow` clauses become `or_()` branches, or separate `@policy` functions (OR'd automatically).

### Role-Based Rules

=== "Before (Polar)"

    ```polar
    allow(actor: User, "edit", post: Post) if
        actor.role = "admin";

    allow(actor: User, "edit", post: Post) if
        post.owner_id = actor.id;
    ```

=== "After (Python)"

    ```python
    @policy(Post, "edit")
    def edit_post(actor: User) -> ColumnElement[bool]:
        if actor.role == "admin":
            return true()
        return Post.owner_id == actor.id
    ```

### Relationship Rules

=== "Before (Polar)"

    ```polar
    allow(actor: User, "read", comment: Comment) if
        post matches Post and
        comment.post = post and
        post.owner_id = actor.id;
    ```

=== "After (Python)"

    ```python
    @policy(Comment, "read")
    def read_comment(actor: User) -> ColumnElement[bool]:
        return Comment.post.has(Post.owner_id == actor.id)
    ```

Use `.has()` for many-to-one, `.any()` for one-to-many. See [Relationship Traversal](../guide/relationships.md).

---

## API Mapping

| Before (Oso) | After (sqla-authz) |
|---|---|
| `authorized_sessionmaker(get_oso=..., get_user=...)` | `authorize_query(stmt, actor=user, action="read")` |
| `session.query(Post).all()` (auto-filtered) | `session.scalars(authorize_query(select(Post), ...)).all()` |
| `Oso(); register_models(oso, Base); oso.load_files(...)` | `import myapp.policies` (policies self-register on import) |
| `oso.authorize(actor, action, resource)` | `authorize(actor, action, resource)` or `can(actor, action, resource)` |

---

## Migration Checklist

1. `pip install sqla-authz`
2. Convert `.polar` files to `@policy` functions — use `or_()` for multiple branches, `.has()`/`.any()` for relationships
3. Migrate to SA 2.0 style — `select(Model)` instead of `session.query(Model)`
4. Replace Oso API calls with `authorize_query()` / `can()` / `authorize()`
5. Remove `from oso import ...` and `from sqlalchemy_oso import ...`
6. `pip uninstall oso sqlalchemy-oso`
7. Run your test suite to verify
