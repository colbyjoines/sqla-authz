# Limitations

This page documents known limitations and boundaries of sqla-authz.

## Point checks vs. query-level authorization

sqla-authz provides two authorization modes:

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

## `explain_access()` limitations

- Creates a temporary SQLite engine per call. Designed for **development and
  debugging only**, not production hot paths.
- Uses SQLite semantics which may differ from your production database
  (e.g., case sensitivity, collation).
- Does not evaluate relationship-based policies (`.has()` / `.any()`).

## Relationship policies

When using `can()` / `authorize()` with policies that reference relationships
(via `.has()` or `.any()`), the relationships **must be loaded** on the instance.
Unloaded relationships are handled according to the `on_unloaded_relationship`
config setting:

- `"deny"` (default): Treat as non-match (access denied).
- `"warn"`: Log a warning and deny.
- `"raise"`: Raise `UnloadedRelationshipError`.

Use `selectinload()` or `joinedload()` to eagerly load relationships before
calling `can()`.

## Project status

sqla-authz is in beta (`v0.1.0b1`). The API is stabilizing but may have
minor changes before `v1.0.0`.
