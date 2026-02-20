# Design Decisions

Key architectural decisions and their rationale.

---

## Pure Python Policies

Policies are `@policy`-decorated Python functions — no DSL, no config files. This gives you type safety (pyright strict), full IDE support (autocomplete, go-to-definition, refactoring), and zero learning curve beyond SQLAlchemy. The tradeoff: Python branching is more verbose than Polar pattern matching for complex role hierarchies.

## Explicit `authorize_query()` by Default

The primary API is `authorize_query()` — visible, greppable, debuggable. Automatic session interception via `do_orm_execute` is opt-in. This makes authorization boundaries easy to find in code review and trivial to step through in a debugger. The tradeoff: one extra line per query, and developers can forget the call (mitigated by the opt-in automatic mode).

## `ColumnElement[bool]` as Output

Policies return `ColumnElement[bool]` directly — the same type used throughout SQLAlchemy for filter expressions. No intermediate representation, no translation layer. The tradeoff: policies using dialect-specific constructs (e.g. PostgreSQL JSONB) aren't portable across databases.

## Deny by Default

Missing policy = `WHERE FALSE` (zero rows). A missing `@policy` declaration can never leak data. Configure `on_missing_policy="raise"` to surface missing policies as errors during development.

## Sync Compilation, Async Execution

The entire policy pipeline is synchronous — lookup, evaluation, filter construction. The async boundary exists only at `session.execute()`. This means the same policy code works identically for `Session` and `AsyncSession`, and `do_orm_execute` event handlers (always sync in SQLAlchemy) work by design. The tradeoff: policies cannot perform async I/O during compilation — all data must be available on the actor object.

## EXISTS over JOIN

Relationship traversal uses `has()`/`any()`, which compile to EXISTS subqueries. EXISTS returns exactly one row per parent entity regardless of relationship cardinality — no duplicates, no `DISTINCT` needed. Modern databases (PostgreSQL, MySQL 8+, SQLite 3.38+) optimize EXISTS into semi-joins, so performance is equivalent to JOIN in practice.
