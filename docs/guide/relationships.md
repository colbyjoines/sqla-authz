# Relationship Traversal

Authorization rules frequently depend on related models. A user can read a post if the post's author belongs to the same organisation. A comment is visible if the parent post is published. These rules require crossing SQLAlchemy relationships inside a policy — and the generated SQL must remain a single, safe WHERE clause.

## The Problem

Consider filtering posts by the author's organisation. The naïve approach loads authors in Python and builds an `in_` list:

```python
# Do NOT do this — N+1 queries, and the list is unbounded
author_ids = session.scalars(
    select(User.id).where(User.org_id == actor.org_id)
).all()
return Post.author_id.in_(author_ids)
```

This is an N+1 pattern that bypasses the database's query planner and breaks for large datasets. The correct approach is an EXISTS subquery — and SQLAlchemy's relationship-aware helpers build one automatically.

## has() vs any()

SQLAlchemy exposes two relationship comparison helpers on mapped attributes:

| Relationship direction | Helper | SQL produced |
|---|---|---|
| `MANYTOONE` (e.g. `Post.author`) | `.has(condition)` | `EXISTS (SELECT 1 FROM user WHERE user.id = post.author_id AND condition)` |
| `ONETOMANY` (e.g. `User.posts`) | `.any(condition)` | `EXISTS (SELECT 1 FROM post WHERE post.author_id = user.id AND condition)` |
| `MANYTOMANY` | `.any(condition)` | `EXISTS (SELECT 1 FROM assoc JOIN target WHERE condition)` |

The rule of thumb: **`has()` for the "one" side, `any()` for the "many" side**.

## Basic Example

Filter posts where the author's org matches the actor's org:

```python
from sqlalchemy import ColumnElement
from sqla_authz import policy

@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    return Post.author.has(User.org_id == actor.org_id)
```

`Post.author` is a `MANYTOONE` relationship (each post has one author), so `.has()` is correct. The generated SQL:

```sql
SELECT post.id, post.title, post.body
FROM post
WHERE EXISTS (
    SELECT 1
    FROM user
    WHERE user.id = post.author_id
      AND user.org_id = :org_id
)
```

No join, no duplicates, no Python-side filtering.

## Multi-hop Traversal

EXISTS subqueries nest naturally for multi-hop paths. Filter posts where the author's organisation is in the actor's approved list:

```python
@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    # Post -> author (MANYTOONE) -> organization (MANYTOONE)
    return Post.author.has(
        User.organization.has(
            Organization.id == actor.org_id
        )
    )
```

Generated SQL:

```sql
WHERE EXISTS (
    SELECT 1
    FROM user
    WHERE user.id = post.author_id
      AND EXISTS (
          SELECT 1
          FROM organization
          WHERE organization.id = user.org_id
            AND organization.id = :org_id
      )
)
```

Each hop becomes a nested EXISTS. The database evaluates these with index seeks — the query planner treats them like correlated subqueries and typically uses the same plan as an equivalent JOIN.

For a `ONETOMANY` hop, use `.any()` instead:

```python
@policy(Department, "read")
def dept_read(actor: User) -> ColumnElement[bool]:
    # Department -> members (ONETOMANY) -> check actor membership
    return Department.members.any(User.id == actor.id)
```

Generated SQL:

```sql
WHERE EXISTS (
    SELECT 1
    FROM user
    WHERE user.department_id = department.id
      AND user.id = :actor_id
)
```

## The EXISTS Strategy

sqla-authz defaults to EXISTS subqueries over JOINs for relationship traversal. The reasons:

**No duplicates.** A JOIN against a `ONETOMANY` relationship produces one row per related child. A blog post with ten comments joined via `post JOIN comment` returns ten rows for that post. EXISTS returns exactly one row per parent — no `DISTINCT` needed, no accidental result inflation.

**Works for all cardinalities.** The same `has()`/`any()` approach works for `MANYTOONE`, `ONETOMANY`, and `MANYTOMANY` without any special casing in your policy code.

**Optimiser-friendly.** Modern databases (PostgreSQL, MySQL 8+, SQLite 3.38+) convert correlated EXISTS subqueries into semi-joins internally. The actual query plan is often identical to the equivalent JOIN, but without the cardinality explosion risk.

**Composable.** EXISTS subqueries nest — multi-hop traversal is just nested `.has()` / `.any()` calls with no additional API surface.

## traverse_relationship_path()

For programmatic traversal where the path is determined at runtime (e.g. from configuration), `traverse_relationship_path` builds the chain automatically:

```python
from sqla_authz.compiler._relationship import traverse_relationship_path
from sqlalchemy import ColumnElement

@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    # Equivalent to Post.author.has(User.org_id == actor.org_id)
    return traverse_relationship_path(
        Post,
        path=["author"],
        leaf_condition=User.org_id == actor.org_id,
    )
```

Multi-hop:

```python
return traverse_relationship_path(
    Post,
    path=["author", "organization"],
    leaf_condition=Organization.id == actor.org_id,
)
```

`traverse_relationship_path` inspects each relationship with `sqlalchemy.inspect()` to determine direction, then calls `.has()` for `MANYTOONE` and `.any()` for `ONETOMANY`/`MANYTOMANY`. The path elements are relationship attribute names on the model at each step.

## Performance Considerations

EXISTS subqueries are efficient when the columns used in the join condition and the leaf condition are indexed.

**Index the foreign key columns.** SQLAlchemy does not create indexes on foreign keys automatically (unlike some ORMs). Add them explicitly:

```python
class Post(Base):
    author_id: Mapped[int] = mapped_column(
        ForeignKey("user.id"),
        index=True,   # essential for EXISTS performance
    )
```

**Index the filter columns in the subquery.** For `User.org_id == actor.org_id`, ensure `user.org_id` is indexed:

```python
class User(Base):
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organization.id"),
        index=True,
    )
```

**EXPLAIN your queries.** For deep multi-hop paths or large tables, run `EXPLAIN ANALYZE` in PostgreSQL (or `EXPLAIN QUERY PLAN` in SQLite) to verify the planner is using index seeks rather than sequential scans. The EXISTS strategy gives the planner the most flexibility to choose an optimal plan.

**Avoid deep chains in hot paths.** Three or more hops create deeply nested EXISTS. For very hot read paths, consider denormalising the join key onto the primary table (e.g. storing `org_id` directly on `Post`) to collapse the traversal to a single column comparison.
