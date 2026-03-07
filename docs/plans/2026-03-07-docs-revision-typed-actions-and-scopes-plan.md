---
title: "docs: Revise documentation for Typed Actions and Scope primitive"
type: docs
status: completed
date: 2026-03-07
deepened: 2026-03-07
reviewed: 2026-03-07
---

# docs: Revise documentation for Typed Actions and Scope primitive

## Enhancement Summary

**Deepened on:** 2026-03-07
**Sections enhanced:** 11 files (up from 9)
**Research agents used:** best-practices-researcher, framework-docs-researcher, repo-research-analyst, code-simplicity-reviewer, writer, spec-flow-analyzer

### Key Improvements from Research
1. **Two missing files discovered** -- `docs/integrations.md` and `docs/migration/from-oso.md` need updates
2. **Critical semantic gap** -- "scopes don't apply when no policies exist" must be documented explicitly
3. **`explain_access()` limitation** -- Does not evaluate scopes; must be documented in limitations.md
4. **Problem-first framing** -- Scopes section should lead with the multi-tenant problem, not the API
5. **Show error output** -- `UnknownActionError` and `UnscopedModelError` messages sell themselves
6. **Style guide codified** -- Strict conventions extracted from existing docs (see Style Guide below)

### Removed from Original Plan (YAGNI / Redundancy)
- Dropped `authz_context` fixture from testing.md (it is a no-op placeholder)
- Dropped top-level action constants tip box from patterns.md (redundant with guide.md)
- Simplified API reference: group action constants as module, not 4 individual entries
- Reduced Scope Patterns section in patterns.md to avoid duplicating guide.md content
- Cut mermaid diagram from Scopes section (prose formula is sufficient)
- Merged "Multiple Scopes" into "How Scopes Compose" (one section, not two)
- Folded "Admin Bypass", "Works Everywhere" into existing sections (not standalone subsections)
- Removed "Common Scope Issues" debugging subsection (premature -- no user feedback yet)
- Removed migration checklist and verify_scopes pattern from patterns.md (already in guide)
- Trimmed style guide from 10 rules to 5 essential ones

---

## Reference Materials

### Implementation source files
- `src/sqla_authz/actions.py` -- `READ`, `UPDATE`, `DELETE`, `CREATE`, `action()`
- `src/sqla_authz/_action_validation.py` -- `check_unknown_action()`, fuzzy matching
- `src/sqla_authz/exceptions.py` -- `UnknownActionError`, `UnscopedModelError`
- `src/sqla_authz/config/_config.py` -- `on_unknown_action` field
- `src/sqla_authz/policy/_scope.py` -- `ScopeRegistration`, `@scope` decorator
- `src/sqla_authz/policy/_registry.py` -- `register_scope()`, `lookup_scopes()`, `has_scopes()`
- `src/sqla_authz/_verify.py` -- `verify_scopes()`
- `src/sqla_authz/__init__.py` -- all new exports

### Design documents (for context, not for editing)
- `docs/brainstorms/2026-03-07-scope-primitive-brainstorm.md`
- `docs/plans/2026-03-07-feat-cross-cutting-scope-primitive-plan.md`
- `.docs/analysis.md`
- `.docs/rfcs/001-typed-actions.md`

### Test files (for usage examples)
- `tests/test_actions.py`
- `tests/test_policy/test_scope.py`
- `tests/test_compiler/test_scope_expression.py`
- `tests/test_verify_scopes.py`
- `tests/test_session/test_scope_interceptor.py`

---

## Style Guide (from repo analysis)

Follow these conventions exactly when writing new sections:

1. **Structure:** `##` for major sections, `###` for subsections, never `####`. Use `---` between `##` sections only. Definition first, then code example, then explanation, then optional admonition.
2. **Code examples:** Always include imports. Use global registry in guide/patterns, explicit `registry=authz_registry` in testing.
3. **Admonitions:** Only `tip`, `warning`, `info`. Always with custom title in quotes. Appear *after* examples, not before. Max one per subsection. Body is 1-3 sentences.
4. **Voice:** Second person ("you"), present tense, active voice. Direct ("Use X" not "You might consider X"). No exclamation marks.
5. **Formatting:** Backticks for identifiers, `()` for callables. Relative links with "See" prefix: `[Title](page.md#anchor)`. Em-dashes: ` -- `.

---

## Prerequisite: Add Inline Docstrings to Action Constants

mkdocstrings requires docstrings to render module-level constants (given `show_if_no_docstring: false` in mkdocs.yml). Add one-line docstrings to `src/sqla_authz/actions.py`:

- [x] Add inline docstrings after each constant:
  ```python
  READ: Final = "read"
  """Built-in action constant for read operations."""

  UPDATE: Final = "update"
  """Built-in action constant for update operations."""

  DELETE: Final = "delete"
  """Built-in action constant for delete operations."""

  CREATE: Final = "create"
  """Built-in action constant for create operations."""
  ```

---

## Detailed Changes by File

### 1. `docs/guide.md`

**Current state:** No mention of typed actions, `on_unknown_action`, `action()` factory, or scopes. The Configuration table is missing `on_unknown_action`.

**Changes needed:**

- [x] **Policies > Defining Policies** -- After the first code example, add a tip box:
  ```
  !!! tip "Action Constants"
      Use `READ`, `UPDATE`, `DELETE`, `CREATE` from `sqla_authz` instead of
      bare strings. They provide IDE autocomplete and prevent typos like
      `"raed"` that silently return zero rows.
      See [Action Safety](#action-safety) below.
  ```

- [x] **New section: "Action Safety"** -- Add after "Custom Registries", before "Relationship Traversal". Separated by `---` above and below.

  Structure:
  1. One-sentence intro: "Action constants and validation catch typos before they cause silent data loss."
  2. Built-in constants example:
     ```python
     from sqla_authz import READ, UPDATE, DELETE, CREATE

     @policy(Post, READ)
     def post_read(actor: User) -> ColumnElement[bool]:
         return Post.is_published == True
     ```
  3. `action()` factory subsection (`###`):
     ```python
     from sqla_authz import action

     PUBLISH = action("publish")
     SOFT_DELETE = action("soft_delete")
     ```
  4. `on_unknown_action` subsection (`###`) with environment recommendation table:

     | Environment | `on_unknown_action` | Why |
     |-------------|--------------------|----|
     | Development | `"warn"` | Catch typos immediately |
     | CI / Tests | `"raise"` | Fail fast on misspelled actions |
     | Production | `"ignore"` (default) | No runtime overhead; rely on CI |

  5. Show the error message output (the fuzzy suggestion sells itself):
     ```python
     configure(on_unknown_action="raise")

     authorize_query(select(Post), actor=user, action="raed")
     # UnknownActionError: Action 'raed' has no registered policies. Did you mean 'read'? Known actions: ['create', 'delete', 'read', 'update']
     ```
  6. Note: `strict_mode=True` sets `on_unknown_action="warn"` automatically.

- [x] **New section: "Scopes"** -- Add after "Relationship Traversal", before "Point Checks". Separated by `---`.

  **Lead with the problem, not the solution** (best practices research):

  1. **"The Multi-Tenant Problem"** (`###`) -- Show the repetitive pattern:
     ```python
     @policy(Post, READ)
     def post_read(actor: User) -> ColumnElement[bool]:
         return (Post.org_id == actor.org_id) & (Post.is_published == True)

     @policy(Comment, READ)
     def comment_read(actor: User) -> ColumnElement[bool]:
         return Comment.org_id == actor.org_id  # easy to forget on new models
     ```
     Then the one-sentence problem statement: "Every policy repeats `Model.org_id == actor.org_id`. If you add a new model and forget this filter, that model's data is visible across tenants."

  2. **"Defining a Scope"** (`###`) -- The solution:
     ```python
     from sqla_authz import scope

     @scope(applies_to=[Post, Comment, Document])
     def tenant(actor: User, Model: type) -> ColumnElement[bool]:
         return Model.org_id == actor.org_id
     ```
     Then: "Now individual policies only express their own logic -- the tenant filter is automatic."
     Brief note: "Register scopes anywhere before query time -- typically in a `scopes.py` module imported at app startup. Scopes and policies can be registered in any order."

  3. **"How Scopes Compose"** (`###`) -- Text formula:
     ```
     final_filter = (policy_1 OR policy_2) AND scope_1 AND scope_2
     ```
     Key semantics (as bullet list):
     - **Policies grant access** -- if any policy matches, the row is a candidate
     - **Scopes restrict access** -- all scopes must match for the row to be returned
     - **No policy = no access** -- scopes cannot override the deny-by-default rule. If no policy exists for a `(model, action)` pair, the result is `WHERE FALSE` regardless of scopes.

     Then show tenant + soft delete as a concrete example of multiple scopes AND'd:
     ```python
     @scope(applies_to=[Post, Comment])
     def tenant(actor: User, Model: type) -> ColumnElement[bool]:
         return Model.org_id == actor.org_id

     @scope(applies_to=[Post, Comment])
     def soft_delete(actor: User, Model: type) -> ColumnElement[bool]:
         return Model.deleted_at.is_(None)
     ```
     Show the generated SQL:
     ```sql
     WHERE (is_published = true OR author_id = :id)
       AND org_id = :org_id
       AND deleted_at IS NULL
     ```

  4. **"Action-Specific Scopes"** (`###`) -- Lead with use case:
     "Some scopes should only apply to certain actions. A soft-delete scope should hide deleted rows from reads but not prevent actual deletions:"
     ```python
     from sqla_authz import READ

     @scope(applies_to=[Post], actions=[READ])
     def soft_delete(actor: User, Model: type) -> ColumnElement[bool]:
         return Model.deleted_at.is_(None)
     ```
     "Without `actions=[READ]`, this scope would also prevent `DELETE` operations on soft-deleted rows."
     Note: "When `actions` is omitted (or `None`), the scope applies to all actions."

  5. **"Bypassing Scopes"** -- Inline in the "Defining a Scope" or "How Scopes Compose" section (not a standalone subsection). Show `true()` bypass pattern inline:
     ```python
     from sqlalchemy import true

     @scope(applies_to=[Post, Comment])
     def tenant(actor: User, Model: type) -> ColumnElement[bool]:
         if actor.role == "admin":
             return true()
         return Model.org_id == actor.org_id
     ```
     Add one sentence: "Returning `true()` bypasses the scope, but policies still apply. To grant unrestricted access, the policy must also return `true()` for admins."

  6. After the bypass example, add one sentence noting scope universality: "Scopes apply to all entry points -- `authorize_query()`, session interception, and `can()`/`authorize()` point checks. Scope expressions used with `can()` must use the supported operator subset. See [Limitations](limitations.md#scope-limitations)."

  7. **"Catching Missing Scopes"** (`###`) -- `verify_scopes()`:
     ```python
     from sqla_authz import verify_scopes

     # In your app startup (e.g., create_app(), FastAPI lifespan)
     verify_scopes(Base, field="org_id")
     ```
     "This checks every subclass of `Base`. If any has an `org_id` column but no registered scope, it raises immediately -- before the application serves requests."
     Show the error output:
     ```python
     verify_scopes(Base, field="org_id")
     # UnscopedModelError: The following models have a 'org_id' column but no registered scope: Invoice, Notification
     ```
     Custom predicate variant:
     ```python
     verify_scopes(Base, when=lambda M: hasattr(M, "org_id"))
     ```
     Note: `field` and `when` are mutually exclusive. All model modules must be imported before calling `verify_scopes()`.
     Tip admonition:
     ```
     !!! tip "Call at Startup or in CI"
         Call `verify_scopes()` during application startup or in your test
         suite -- never in the request path. It scans all model classes,
         which is a one-time cost at boot.
     ```

- [x] **Configuration table** -- Add `on_unknown_action` row:

  | Field | Default | Description |
  |-------|---------|-------------|
  | `on_unknown_action` | `"ignore"` | Action not found in registry: `"ignore"` silent (backward compatible); `"warn"` logs with suggestions; `"raise"` throws `UnknownActionError` |

---

### 2. `docs/patterns.md`

**Current state:** Shows manual `Post.org_id == actor.org_id` in every policy for multi-tenant.

**Changes needed:**

- [x] **"Multi-tenant with role scoping"** subsection -- Keep the existing policy example, add a callout box after it:
  ```
  !!! tip "Use Scopes for Tenant Isolation"
      Instead of repeating `Document.org_id == actor.org_id` in every
      policy, use a scope to apply it automatically.
      See [Scopes](guide.md#scopes) for the full guide.
  ```

- [x] **New section: "Scope Patterns"** -- Add after "Composable predicates", before "Query-level authorization". Separated by `---`.

  Focus on patterns NOT already covered in the Guide (avoid duplication):

  1. **Combining action-specific and universal scopes** -- Show tenant scope (all actions) + soft-delete scope (read only) on the same model, with a brief explanation of the resulting behavior per action.

---

### 3. `docs/getting-started.md`

**Current state:** Uses bare `"read"` strings throughout. No mention of action constants, scopes, or `verify_scopes`.

**Changes needed:**

- [x] In **"Quick Start > 2. Write a policy"** -- Show `READ` constant as alternative with inline comment:
  ```python
  from sqla_authz import policy, READ

  @policy(Post, READ)  # or @policy(Post, "read") -- bare strings still work
  def post_read_policy(actor: User) -> ColumnElement[bool]:
      ...
  ```
- [x] In **"Quick Start > 3. Authorize a query"** -- Same treatment:
  ```python
  stmt = authorize_query(stmt, actor=current_user, action=READ)
  ```
- [x] In **"Core Concepts > The Registry"** -- Add a brief paragraph: "Action constants like `READ` and `UPDATE` prevent typo bugs that silently return zero rows. See [Action Safety](guide.md#action-safety) for details."
- [x] In **"Core Concepts"** -- Add **"Scopes"** subsection (`###`) after "ActorLike Protocol" (not before -- ActorLike is a prerequisite concept for understanding scopes).

  Lead with the problem: "In a multi-tenant app, every policy must include a tenant filter. Forgetting it on one model leaks data across tenants." Then the solution: scopes are cross-cutting filters AND'd with policies. One example:
  ```python
  from sqla_authz import scope

  @scope(applies_to=[Post, Comment, Document])
  def tenant(actor: User, Model: type) -> ColumnElement[bool]:
      return Model.org_id == actor.org_id
  ```
  Then: "See [Scopes](guide.md#scopes) for the full guide and [Scope Patterns](patterns.md#scope-patterns) for real-world examples."

---

### 4. `docs/testing.md`

**Current state:** No mention of scopes in test fixtures, no mention of action constants.

**Changes needed:**

- [x]**"Pytest Fixtures" section** -- Add `isolated_authz_state` fixture:
  - `isolated_authz_state` -- Saves and restores the global registry state (including scopes) around a test. Prevents module-level registrations from leaking.
  (Do NOT add `authz_context` -- it is currently a no-op placeholder.)

- [x]**New section: "Testing Scopes"** -- Add after "Pytest Fixtures". Open with: "See [Scopes](guide.md#scopes) for how scopes work." Include both positive and negative test patterns:
  ```python
  def test_tenant_scope_isolates_data(authz_registry):
      @scope(applies_to=[Post], registry=authz_registry)
      def tenant(actor, Model):
          return Model.org_id == actor.org_id

      @policy(Post, READ, registry=authz_registry)
      def allow(actor):
          return true()

      # Positive: scope filter appears in SQL
      assert_query_contains(
          select(Post), actor=make_user(id=1, org_id=42),
          action=READ, text="org_id", registry=authz_registry,
      )

  def test_all_tenant_models_have_scopes(authz_registry):
      """Catch new models added without a tenant scope."""
      # Register your scopes before calling verify_scopes --
      # an empty registry trivially passes (no scopes to miss).
      register_all_scopes(authz_registry)
      verify_scopes(Base, field="org_id", registry=authz_registry)
  ```

- [x]**Update one existing example** -- Use `READ` constant instead of `"read"` in at least one example to show best practice.

---

### 5. `docs/limitations.md`

**Current state:** Correct but incomplete. No mention of scope limitations.

**Changes needed:**

- [x]**"Point checks vs. query-level authorization" section** -- Add a note: "Scopes work identically in both paths -- they return `ColumnElement[bool]` and go through the same `evaluate_policies()` function. However, scope expressions used with `can()`/`authorize()` must use the supported operator subset listed above."

- [x]**New section: "Scope limitations"** (`##`, separated by `---`):
  - Scopes are evaluated per-query, not cached. This is by design -- actor attributes may change between requests.
  - `verify_scopes()` only checks column presence (field-based) or custom predicate (when-based). It cannot detect if a scope's logic is correct.
  - `verify_scopes()` scans `DeclarativeBase.__subclasses__()` -- all mapped classes must be imported before calling it.
  - `explain_access()` and `explain_query()` do not currently include scope information in their output. Use `authorize_query()` with `.compile(compile_kwargs={"literal_binds": True})` to inspect the full SQL including scopes.

---

### 6. `docs/reference/api.md`

**Current state:** Missing all new symbols.

**Changes needed:**

- [x]**New section: "Actions"** (`##`) -- Add after "Core". Use module-level grouping:
  ```markdown
  ## Actions

  ::: sqla_authz.actions
      options:
        show_root_heading: true
        show_if_no_docstring: true
        members:
          - READ
          - UPDATE
          - DELETE
          - CREATE
          - action
  ```

- [x]**New section: "Scopes"** (`##`) -- Add after "Predicates":
  ```markdown
  ## Scopes

  ::: sqla_authz.scope
      options:
        show_root_heading: true

  ::: sqla_authz.policy._scope.ScopeRegistration
      options:
        show_root_heading: true

  ::: sqla_authz.verify_scopes
      options:
        show_root_heading: true
  ```

- [x]**PolicyRegistry section** -- Expand members list:
  ```markdown
  ::: sqla_authz.PolicyRegistry
      options:
        show_root_heading: true
        members:
          - register
          - lookup
          - has_policy
          - registered_entities
          - register_scope
          - lookup_scopes
          - has_scopes
          - known_actions
          - known_actions_for
          - clear
  ```

- [x]**Exceptions section** -- Add `UnknownActionError`, `UnscopedModelError`:
  ```markdown
  ::: sqla_authz.exceptions
      options:
        show_root_heading: true
        members:
          - AuthzError
          - AuthorizationDenied
          - NoPolicyError
          - PolicyCompilationError
          - UnknownActionError
          - UnscopedModelError
          - WriteDeniedError
  ```

---

### 7. `docs/index.md`

**Current state:** Hero example uses bare `"read"` string. No mention of scopes.

**Changes needed:**

- [x]**Hero code example** -- Keep as-is (bare strings are simpler for first impressions).
- [x]**"How it works" section** -- Add one sentence after "The compiler OR's multiple policies together...": "Scopes provide cross-cutting filters (like tenant isolation) that are automatically AND'd with all policies."
- [x]**Navigation links** -- Add "Common Patterns" to the link list at the bottom:
  ```markdown
  - [Common Patterns](patterns.md) — RBAC, ABAC, scopes, composable predicates
  ```

---

### 8. `docs/integrations.md`

**Current state:** Shows `AuthzDep(Post, "read")` with bare string actions. No mention of scopes.

**Changes needed:**

- [x]After the `AuthzDep` example, add a brief inline note showing the constant form: `AuthzDep(Post, READ)` as an alternative.
- [x]Add one sentence noting that scopes work automatically with `AuthzDep` and session interception: "Scopes are automatically applied alongside policies through all entry points, including `AuthzDep`. See [Scopes](guide.md#scopes) for details."

---

### 9. `docs/migration/from-oso.md`

**Current state:** Uses bare strings throughout. No mention of scopes or typed actions.

**Changes needed:**

- [x]In the concept mapping table, add a row for scopes: `@scope()` as sqla-authz's cross-cutting filter mechanism.
- [x]In "Known Limitations vs Oso", update relevant rows to note that scopes address cross-cutting authorization patterns.
- [x]Optionally add a note in the migration checklist about using `verify_scopes()` to catch models that need explicit scope coverage.

---

### 10. `.docs/analysis.md` (internal)

**Current state:** Issues #1 (typed actions) and #2 (scope) listed as unresolved.

**Changes needed:**

- [x]Add a status block at the top of the file (do not edit the analysis body text):
  ```markdown
  > **Status Update (2026-03-07):**
  > - Issue #1 (Actions are untyped): **Resolved** -- `READ`/`UPDATE`/`DELETE`/`CREATE` constants, `action()` factory, `on_unknown_action` config, `UnknownActionError` with fuzzy suggestions
  > - Issue #2 (No multi-tenant scoping): **Resolved** -- `@scope()` decorator, `verify_scopes()` safety net, scopes AND'd with OR'd policies
  ```

---

### 11. `.docs/rfcs/001-typed-actions.md` (internal)

**Current state:** Status is "Draft".

**Changes needed:**

- [x]Change status from `Draft` to `Implemented`
- [x]Add a brief "Implementation Notes" section noting the approach: constants + factory + config (not enum class)

---

## Implementation Notes

### Ordering
Process narrative docs first, then mechanical/internal docs:
1. `docs/guide.md` (largest changes -- Action Safety and Scopes sections)
2. `docs/patterns.md` (Scope Patterns section + callout)
3. `docs/getting-started.md` (smaller additions)
4. `docs/testing.md` (Testing Scopes section)
5. `docs/limitations.md` (Scope limitations section)
6. `docs/index.md` (one sentence + nav link)
7. `docs/integrations.md` (one sentence + constant example)
8. `docs/migration/from-oso.md` (table row + notes)
9. `docs/reference/api.md` (mechanical mkdocstrings directives)
10. `.docs/analysis.md` (status block)
11. `.docs/rfcs/001-typed-actions.md` (status update)

### Prerequisite
- Add inline docstrings to `src/sqla_authz/actions.py` constants (see Prerequisite section above)

### What NOT to change
- Don't replace existing bare string examples wholesale -- they're still valid and simpler for first exposure
- Don't restructure existing sections -- add new sections in logical positions
- Don't remove the manual tenant isolation example from patterns.md -- it's still valid, the callout notes scopes are the recommended approach
- Don't edit the body text of `.docs/analysis.md` -- add a status block at the top only

### Post-Implementation Verification
- [x]Verify all code examples include necessary imports
- [x]Verify all cross-reference links have valid anchors (check `#anchor` targets exist)
- [x]Verify mkdocstrings renders new API entries (run `mkdocs serve` locally)
- [x]Verify action constant docstrings render in API reference
- [x]Ensure no duplicate content between guide.md Scopes and patterns.md Scope Patterns

### Follow-Up Implementation Issues (out of scope for docs revision)
These are implementation gaps discovered during research that should be filed as separate issues:
1. `explain_access()` should call `registry.lookup_scopes()` and include scope evaluations
2. `explain_query()` should AND scope filters into the combined expression
3. `simulate_query()` should include a `scopes_applied` field on `SimulationResult`
4. Audit logging in `evaluate_policies()` should log which scopes were applied at DEBUG level
5. `AuthzConfig.merge()` docstring is missing `on_unknown_action` in its Args section
