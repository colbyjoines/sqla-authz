# Limitations

## Point checks vs. query-level authorization

| Feature | `authorize_query()` | `can()` / `authorize()` |
|---------|---------------------|------------------------|
| Execution | Database (SQL WHERE) | In-memory (AST walk) |
| Supports all SQL operators | Yes | Limited subset |
| Handles relationships | Yes (via JOINs) | Yes (if loaded) |
| Performance | Database-optimized | No DB round-trip |

### Supported operators for point checks

The in-memory evaluator (`can()` / `authorize()`) supports:

- **Comparison:** `==`, `!=`, `<`, `<=`, `>`, `>=`
- **Identity:** `is_`, `is_not` (NULL checks)
- **Membership:** `in_`, `not_in`
- **Pattern matching:** `like`, `ilike`, `not_like`, `not_ilike`
- **Range:** `between`
- **String:** `contains`, `startswith`, `endswith`
- **Boolean logic:** `and_`, `or_`, `not_` (via `~`)
- **Literals:** `true()`, `false()`
- **Relationships:** `.has()`, `.any()` (requires loaded relationships)

### Unsupported operators for point checks

These raise `UnsupportedExpressionError` in `can()` / `authorize()` but work
in `authorize_query()`:

- `func.*()` (SQL functions like `func.lower()`, `func.count()`)
- `regexp_match` (database-specific regex)
- `concat`, `collate` (string manipulation)
- Aggregate functions
- Subqueries (non-relationship)
- Database-specific operators (e.g., PostgreSQL array operators)

### Marking policies as query-only

If your policy uses SQL constructs not supported by the in-memory evaluator,
mark it with ``query_only=True`` to get a clear error at ``can()`` / ``authorize()``
call sites instead of an opaque ``UnsupportedExpressionError``:

```python
@policy(Post, "read", query_only=True)
def complex_read(actor: User) -> ColumnElement[bool]:
    return func.lower(Post.category) == "public"

can(user, "read", post)  # raises QueryOnlyPolicyError with clear message
```

Policies marked ``query_only=True`` work normally with ``authorize_query()``
and ``explain_access()``. Only ``can()`` and ``authorize()`` are guarded.

---

## Project status

sqla-authz is in beta (`v0.1.0b1`). The API is stabilizing but may have
minor changes before `v1.0.0`.
