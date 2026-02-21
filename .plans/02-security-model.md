# Plan 02: Security Model — Bypass Inventory, Strict Mode & Audit Logging

## Status: DRAFT
## Priority: HIGH — security-critical

---

## 1. Complete Bypass Vector Inventory

### Bypass 1: `session.get()` — SILENT, UNDOCUMENTED

**Location:** `_interceptor.py:39`
```python
if orm_execute_state.is_column_load or orm_execute_state.is_relationship_load:
    return
```

**Mechanism:** `session.get(Post, 1)` triggers `do_orm_execute` with `is_column_load=True`. The interceptor explicitly skips column loads, so the row is returned without any policy filtering.

**Severity:** HIGH — This is the most dangerous bypass because:
- It is completely silent (no log, no warning, no error).
- It is a natural, idiomatic SQLAlchemy pattern that developers will use without thinking.
- It returns the full unfiltered object, which can then leak into templates/serializers.
- The `session.get()` docstring and our own docs make no mention of this behavior.

**Why the skip exists:** Column loads and relationship loads are internal SQLAlchemy mechanisms for populating attributes on already-loaded objects (e.g., deferred column access, expired attribute refresh). Intercepting these would:
1. Break the identity map contract — an object already in the session would suddenly become inaccessible.
2. Cause infinite recursion — policy evaluation itself might trigger attribute loads.
3. Break legitimate patterns like loading the current user (`session.get(User, current_user_id)`).

**Risk if intercepted naively:** High. If we applied `WHERE` filters to column loads, SQLAlchemy would raise errors or silently lose already-loaded objects from the identity map. This would break `session.refresh()`, deferred column access, and lazy attribute loading.

### Bypass 2: `text()` Queries — SILENT

**Mechanism:** `session.execute(text("SELECT * FROM posts"))` — the interceptor sees `is_select=True` but when it casts to `Select` and reads `column_descriptions`, there are no ORM entities (it's a textual SQL statement). The `for desc in desc_list` loop finds no entities and applies no filters.

**Severity:** MEDIUM-HIGH — Raw SQL bypasses all ORM-level authorization. This is somewhat expected (you opted out of the ORM), but the silence is dangerous. A developer might use `text()` for performance and not realize they've bypassed authz.

**Location:** `_interceptor.py:49-58` — the loop simply finds no entities to filter.

### Bypass 3: `skip_authz=True` — INTENTIONAL, UNDOCUMENTED RISK

**Location:** `_interceptor.py:43-44`
```python
if orm_execute_state.execution_options.get("skip_authz", False):
    return
```

**Mechanism:** `execution_options(skip_authz=True)` is an intentional escape hatch. However:
- There is no audit trail when it is used.
- It could be set accidentally via middleware, a base query class, or copy-paste.
- There is no way to restrict which callers can use it.

**Severity:** LOW (by design) — but should be logged.

### Bypass 4: Bulk UPDATE/DELETE — BY DESIGN, NO WRITE-AUTHZ PATH

**Location:** `_interceptor.py:35-36`
```python
if not orm_execute_state.is_select:
    return
```

**Mechanism:** `session.execute(update(Post).values(title="hacked"))` and `session.execute(delete(Post).where(...))` are correctly skipped because the interceptor is read-only. However, there is no corresponding write-authorization mechanism.

**Severity:** MEDIUM — This is a design limitation, not a bug. But it should be documented as an explicit non-goal or future work item. Users need to know that the interceptor only protects reads.

### Bypass 5: Core `select()` Without ORM Entities

**Mechanism:** `session.execute(select(Post.__table__.c.id, Post.__table__.c.title))` — selecting from core `Table.c` columns rather than ORM mapped classes. `column_descriptions` will have `entity=None` for each column, so no policies are applied.

**Severity:** MEDIUM — Similar to `text()` but slightly more subtle because it uses the `select()` construct.

**Location:** `_interceptor.py:54-55` — `entity` is `None`, `continue` skips it.

### Bypass 6: `from_statement()` with Raw SQL

**Mechanism:** `session.execute(select(Post).from_statement(text("SELECT * FROM posts")))` — the ORM entity is present in `column_descriptions`, but the actual SQL executed is the raw text. Policies would be applied to the outer `Select` wrapper, but the inner `text()` provides the actual rows. The `WHERE` clause added by the interceptor may be silently ignored or cause a SQL error depending on the dialect.

**Severity:** MEDIUM — Edge case but worth documenting.

### Bypass 7: Identity Map Cache

**Mechanism:** If an object was previously loaded into the session's identity map (via any means, including an unprotected `session.get()` or a `skip_authz` query), subsequent ORM queries that reference that primary key may return the cached object without re-executing SQL. The interceptor only fires on actual SQL execution, not on identity map hits.

**Severity:** LOW — This is a SQLAlchemy feature, not a sqla-authz bug. But it means that authorization decisions are only as fresh as the session's identity map.

---

## 2. Decision: Should `session.get()` Be Intercepted?

### Recommendation: NO — Do NOT intercept `session.get()` directly.

### Rationale:

1. **Technical infeasibility:** `is_column_load=True` covers both `session.get()` AND internal SQLAlchemy attribute refreshes (deferred columns, expired attributes). There is no way to distinguish "user called `session.get()`" from "SQLAlchemy is refreshing an expired attribute" inside the `do_orm_execute` hook. Intercepting all column loads would break fundamental ORM behavior.

2. **Identity map semantics:** `session.get()` checks the identity map first. If the object is already loaded, no SQL is executed at all — the interceptor never fires. So even if we intercepted the SQL path, behavior would be inconsistent depending on whether the object was already cached.

3. **Legitimate use cases:** Loading the current user (`session.get(User, token.user_id)`) is the canonical example of a load that MUST work without authorization filters. Applying read policies to the current user lookup would create a bootstrap paradox.

4. **Industry precedent:** Oso, Cerbos, and Django Guardian all treat direct PK lookups as outside the query-level authorization boundary. Post-load point checks (`can()` / `authorize()`) are the standard pattern.

### Mitigation Strategy:

Instead of intercepting `session.get()`, we will:

1. **Document it prominently** as a known bypass with recommended patterns.
2. **Provide `safe_get()` helper** that wraps `session.get()` + `can()` check.
3. **Add strict mode warning/error** when `session.get()` is called on a protected entity.
4. **Audit log** all `session.get()` calls on entities with registered policies.

---

## 3. Strict Mode Design

### 3.1 New Config Options

Add to `AuthzConfig`:

```python
@dataclass(frozen=True, slots=True)
class AuthzConfig:
    on_missing_policy: str = "deny"
    default_action: str = "read"
    log_policy_decisions: bool = False

    # NEW fields:
    strict_mode: bool = False
    on_unprotected_get: str = "ignore"       # "ignore" | "warn" | "raise"
    on_text_query: str = "ignore"            # "ignore" | "warn" | "raise"
    on_skip_authz: str = "ignore"            # "ignore" | "warn" | "log"
    audit_bypasses: bool = False             # Log ALL bypass events
```

**`strict_mode=True`** is a convenience shorthand that sets:
- `on_unprotected_get = "warn"`
- `on_text_query = "warn"`
- `on_skip_authz = "log"`
- `audit_bypasses = True`

Individual settings override the strict_mode defaults when explicitly provided.

### 3.2 Merge Semantics

Extend `AuthzConfig.merge()` to handle all new fields with the same `None`-means-inherit pattern:

```python
def merge(self, *, strict_mode=None, on_unprotected_get=None, ...):
    effective_strict = strict_mode if strict_mode is not None else self.strict_mode
    # If strict_mode changed to True and individual setting not explicitly given,
    # apply strict defaults
    ...
```

### 3.3 Interceptor Behavior Changes

Modify `_apply_authz` in `_interceptor.py`:

```python
def _apply_authz(orm_execute_state: ORMExecuteState) -> None:
    # --- Bypass: non-SELECT ---
    if not orm_execute_state.is_select:
        return

    # --- Bypass: column/relationship loads (session.get(), deferred, etc.) ---
    if orm_execute_state.is_column_load or orm_execute_state.is_relationship_load:
        if target_config.audit_bypasses or target_config.on_unprotected_get != "ignore":
            _handle_column_load_bypass(orm_execute_state, target_config, target_registry)
        return  # Always return — never filter column loads

    # --- Bypass: skip_authz ---
    if orm_execute_state.execution_options.get("skip_authz", False):
        if target_config.audit_bypasses or target_config.on_skip_authz != "ignore":
            _handle_skip_authz_bypass(orm_execute_state, target_config)
        return

    # ... existing policy application logic ...

    # --- Check: no ORM entities found (text() or core queries) ---
    if not queried_entities:
        if target_config.audit_bypasses or target_config.on_text_query != "ignore":
            _handle_no_entity_bypass(orm_execute_state, target_config)
```

### 3.4 Bypass Handler Functions

New private module: `src/sqla_authz/session/_bypass_handlers.py`

```python
import logging
import warnings

from sqla_authz.exceptions import AuthzBypassError

logger = logging.getLogger("sqla_authz.bypass")

def _handle_column_load_bypass(state, config, registry):
    """Handle session.get() / column load bypass."""
    # Try to identify the entity from the statement
    entity = _extract_entity_from_column_load(state)
    if entity and registry.has_policy(entity, config.default_action):
        msg = (
            f"Unprotected column load for {entity.__name__} — "
            f"session.get() bypasses authorization. "
            f"Use can(actor, action, obj) for post-load checks."
        )
        if config.on_unprotected_get == "raise":
            raise AuthzBypassError(msg)
        elif config.on_unprotected_get == "warn":
            warnings.warn(msg, SecurityWarning, stacklevel=4)
        if config.audit_bypasses:
            logger.warning("BYPASS:column_load — %s", msg)

def _handle_skip_authz_bypass(state, config):
    """Handle skip_authz=True bypass."""
    msg = "skip_authz=True used — authorization bypassed"
    if config.on_skip_authz == "log":
        logger.info("BYPASS:skip_authz — %s", msg)
    elif config.on_skip_authz == "warn":
        warnings.warn(msg, SecurityWarning, stacklevel=4)
    if config.audit_bypasses:
        logger.warning("BYPASS:skip_authz — %s", msg)

def _handle_no_entity_bypass(state, config):
    """Handle text() or core query with no ORM entities."""
    msg = "Query has no ORM entities — authorization not applied (text() or core query)"
    if config.on_text_query == "raise":
        raise AuthzBypassError(msg)
    elif config.on_text_query == "warn":
        warnings.warn(msg, SecurityWarning, stacklevel=4)
    if config.audit_bypasses:
        logger.warning("BYPASS:no_entity — %s", msg)
```

### 3.5 New Exception

Add to `exceptions.py`:

```python
class AuthzBypassError(AuthzError):
    """Raised in strict mode when an unprotected access pattern is detected."""
```

### 3.6 SecurityWarning

Use Python's built-in `warnings` module with a custom `SecurityWarning` category so users can control behavior via `warnings.filterwarnings()`. This integrates with pytest's warning capture and standard Python warning infrastructure.

---

## 4. Audit Logging Enhancements

### 4.1 New Logger Hierarchy

```
sqla_authz              — existing policy evaluation logs
sqla_authz.bypass       — NEW: bypass event logs
sqla_authz.bypass.column_load
sqla_authz.bypass.skip_authz
sqla_authz.bypass.text_query
```

### 4.2 Structured Log Fields

Each bypass log entry should include (at DEBUG level):
- `event`: bypass type (`column_load`, `skip_authz`, `text_query`)
- `entity`: model class name (if identifiable)
- `statement`: abbreviated SQL (first 200 chars)
- `stack_hint`: caller filename + line number (2 frames up from the interceptor)

### 4.3 Audit Module Changes

Extend `_audit.py` with a new function:

```python
def log_bypass_event(
    *,
    bypass_type: str,
    entity: type | None = None,
    statement_hint: str = "",
    detail: str = "",
) -> None:
    bypass_logger = logging.getLogger(f"sqla_authz.bypass.{bypass_type}")
    bypass_logger.warning(
        "BYPASS:%s entity=%s stmt=%s — %s",
        bypass_type,
        entity.__name__ if entity else "<unknown>",
        statement_hint[:200],
        detail,
    )
```

---

## 5. `safe_get()` Helper

Provide a convenience function that combines `session.get()` with a post-load authorization check:

**File:** `src/sqla_authz/session/_safe_get.py`

```python
from sqla_authz._checks import can
from sqla_authz.exceptions import AuthorizationDenied

def safe_get(
    session,
    entity_class,
    pk,
    *,
    actor,
    action="read",
    registry=None,
):
    """Load an entity by PK and verify authorization.

    Returns None if the entity doesn't exist or if access is denied.
    Use safe_get_or_raise() for the raising variant.
    """
    obj = session.get(entity_class, pk)
    if obj is None:
        return None
    if not can(actor, action, obj, registry=registry):
        return None
    return obj

def safe_get_or_raise(
    session,
    entity_class,
    pk,
    *,
    actor,
    action="read",
    registry=None,
    message=None,
):
    """Load an entity by PK and assert authorization.

    Raises AuthorizationDenied if the actor is not authorized.
    Returns the entity on success.
    """
    obj = session.get(entity_class, pk)
    if obj is None:
        return None
    if not can(actor, action, obj, registry=registry):
        raise AuthorizationDenied(
            actor=actor,
            action=action,
            resource_type=entity_class.__name__,
            message=message,
        )
    return obj
```

Export from `__init__.py` as `safe_get` and `safe_get_or_raise`.

---

## 6. Documentation Outline

### 6.1 New Page: `docs/security-model.md`

```
# Security Model

## Authorization Boundary
- What the interceptor protects (ORM SELECT queries)
- What it does NOT protect (session.get, text(), bulk DML, core queries)

## Bypass Vectors
### session.get() — Identity Lookup Bypass
- Why it exists (technical constraints)
- How to mitigate (safe_get, can(), strict mode)
- Code example showing the bypass and the fix

### text() Queries
- Why raw SQL bypasses authorization
- Recommended pattern: always use ORM queries for authorized access

### skip_authz Escape Hatch
- When to use it (migrations, admin tools, background jobs)
- How to audit its usage

### Bulk UPDATE/DELETE
- Why write-authorization is out of scope
- Recommended patterns for write checks

### Core Table Queries
- select(Model.__table__.c.col) bypasses entity detection
- Use select(Model) instead

### Identity Map Caching
- How SQLAlchemy's identity map interacts with authorization
- Session lifecycle recommendations

## Strict Mode
- Configuration reference
- What each setting does
- Recommended settings per environment (dev/staging/prod)

## Audit Logging
- Logger hierarchy
- Log levels and when each fires
- Integration with structured logging (JSON)

## Recommendations by Use Case
- Web API (FastAPI): strict_mode=True, on_missing_policy="raise"
- Admin/Internal Tool: skip_authz for admin routes, audit_bypasses=True
- Background Jobs: explicit skip_authz with logging
- Multi-tenant: per-session registry + strict_mode
```

### 6.2 Update Existing Docs

- `docs/guide.md` — Add "Security Considerations" callout box in Session Interception section pointing to the security model page.
- `docs/reference/api.md` — Add `safe_get`, `safe_get_or_raise`, `AuthzBypassError`, and new `AuthzConfig` fields.

---

## 7. Implementation Steps (File by File)

### Step 1: Exceptions (`src/sqla_authz/exceptions.py`)
- Add `AuthzBypassError` exception class.
- Add to `__all__`.
- **Estimated diff:** +10 lines.

### Step 2: Config (`src/sqla_authz/config/_config.py`)
- Add new fields to `AuthzConfig`: `strict_mode`, `on_unprotected_get`, `on_text_query`, `on_skip_authz`, `audit_bypasses`.
- Update `merge()` to handle new fields.
- Update `configure()` to accept new keyword arguments.
- Add `_resolve_strict_defaults()` private helper that applies strict_mode convenience defaults.
- **Estimated diff:** +50 lines.

### Step 3: Audit module (`src/sqla_authz/_audit.py`)
- Add `log_bypass_event()` function.
- Add bypass-specific logger hierarchy.
- Add to `__all__`.
- **Estimated diff:** +30 lines.

### Step 4: Bypass handlers (`src/sqla_authz/session/_bypass_handlers.py`) — NEW FILE
- Implement `_handle_column_load_bypass()`.
- Implement `_handle_skip_authz_bypass()`.
- Implement `_handle_no_entity_bypass()`.
- Implement `_extract_entity_from_column_load()` helper.
- **Estimated diff:** +80 lines.

### Step 5: Interceptor (`src/sqla_authz/session/_interceptor.py`)
- Import bypass handlers.
- Add bypass handler calls at each early-return point.
- Track `queried_entities` and call `_handle_no_entity_bypass` when empty.
- Pass `target_config` through to handlers.
- **Estimated diff:** +25 lines modified.

### Step 6: `safe_get` helper (`src/sqla_authz/session/_safe_get.py`) — NEW FILE
- Implement `safe_get()` and `safe_get_or_raise()`.
- **Estimated diff:** +60 lines.

### Step 7: Public API (`src/sqla_authz/__init__.py`)
- Export `safe_get`, `safe_get_or_raise`, `AuthzBypassError`.
- **Estimated diff:** +5 lines.

### Step 8: Tests (see section 8 below)

### Step 9: Documentation
- Create `docs/security-model.md`.
- Update `docs/guide.md` with security callout.
- Update `docs/reference/api.md` with new API entries.

---

## 8. Test Cases

### 8.1 Bypass Behavior Tests (`tests/test_session/test_bypasses.py`) — NEW FILE

```python
class TestSessionGetBypass:
    """Verify session.get() bypasses authorization (current behavior)."""

    def test_session_get_returns_unfiltered_object(self):
        """session.get() should return objects even when policy would deny."""
        # Setup: deny-all policy for Post
        # Action: session.get(Post, 1)
        # Assert: returns the Post (bypass confirmed)

    def test_session_get_identity_map_hit_no_sql(self):
        """session.get() on an already-loaded object doesn't execute SQL."""
        # Verify the interceptor is never called for identity map hits.

class TestTextQueryBypass:
    """Verify text() queries bypass authorization."""

    def test_text_query_returns_unfiltered_results(self):
        """text() queries should bypass all policy filtering."""
        # Setup: deny-all policy for Post
        # Action: session.execute(text("SELECT * FROM posts"))
        # Assert: returns all posts

    def test_core_table_query_bypasses_authorization(self):
        """Selecting from Table.c columns bypasses entity detection."""
        # Setup: deny-all policy for Post
        # Action: session.execute(select(Post.__table__.c.id))
        # Assert: returns all post IDs

class TestSkipAuthzBypass:
    """Verify skip_authz=True behavior."""

    # These tests already exist in test_interceptor.py but we add:

    def test_skip_authz_on_sessionmaker_level(self):
        """execution_options set at the sessionmaker level bypass all queries."""

class TestBulkOperationBypass:
    """Verify bulk UPDATE/DELETE are not intercepted."""

    # These tests already exist but verify explicitly:

    def test_bulk_update_not_intercepted(self):
        """Bulk update() bypasses the read interceptor."""

    def test_bulk_delete_not_intercepted(self):
        """Bulk delete() bypasses the read interceptor."""
```

### 8.2 Strict Mode Tests (`tests/test_session/test_strict_mode.py`) — NEW FILE

```python
class TestStrictModeColumnLoad:
    """Test on_unprotected_get behavior."""

    def test_ignore_mode_no_warning(self):
        """Default: session.get() produces no warning."""

    def test_warn_mode_emits_warning(self):
        """on_unprotected_get='warn': session.get() emits SecurityWarning."""

    def test_raise_mode_raises_error(self):
        """on_unprotected_get='raise': session.get() raises AuthzBypassError."""

    def test_no_warning_for_entity_without_policy(self):
        """session.get() on an entity with no policy should not warn."""

class TestStrictModeTextQuery:
    """Test on_text_query behavior."""

    def test_ignore_mode_no_warning(self):
        """Default: text() queries produce no warning."""

    def test_warn_mode_emits_warning(self):
        """on_text_query='warn': text() queries emit SecurityWarning."""

    def test_raise_mode_raises_error(self):
        """on_text_query='raise': text() queries raise AuthzBypassError."""

class TestStrictModeSkipAuthz:
    """Test on_skip_authz behavior."""

    def test_ignore_mode_no_log(self):
        """Default: skip_authz produces no log."""

    def test_log_mode_logs_warning(self):
        """on_skip_authz='log': skip_authz emits log entry."""

    def test_warn_mode_emits_warning(self):
        """on_skip_authz='warn': skip_authz emits SecurityWarning."""

class TestStrictModeConvenience:
    """Test strict_mode=True convenience flag."""

    def test_strict_mode_sets_defaults(self):
        """strict_mode=True should set warn/log defaults."""

    def test_explicit_overrides_strict_defaults(self):
        """Explicit per-field settings override strict_mode defaults."""
```

### 8.3 Audit Bypass Tests (`tests/test_audit_bypass.py`) — NEW FILE

```python
class TestAuditBypassLogging:
    """Test bypass audit logging."""

    def test_column_load_bypass_logged(self):
        """audit_bypasses=True logs session.get() bypass."""

    def test_skip_authz_bypass_logged(self):
        """audit_bypasses=True logs skip_authz usage."""

    def test_text_query_bypass_logged(self):
        """audit_bypasses=True logs text() query bypass."""

    def test_no_logging_when_disabled(self):
        """audit_bypasses=False produces no bypass logs."""

    def test_log_includes_entity_name(self):
        """Bypass logs include the entity class name."""
```

### 8.4 `safe_get` Tests (`tests/test_session/test_safe_get.py`) — NEW FILE

```python
class TestSafeGet:
    """Test safe_get() authorized lookup."""

    def test_returns_authorized_object(self):
        """safe_get returns the object when policy allows."""

    def test_returns_none_when_denied(self):
        """safe_get returns None when policy denies."""

    def test_returns_none_when_not_found(self):
        """safe_get returns None when PK doesn't exist."""

class TestSafeGetOrRaise:
    """Test safe_get_or_raise() authorized lookup."""

    def test_returns_authorized_object(self):
        """safe_get_or_raise returns the object when policy allows."""

    def test_raises_when_denied(self):
        """safe_get_or_raise raises AuthorizationDenied when policy denies."""

    def test_returns_none_when_not_found(self):
        """safe_get_or_raise returns None when PK doesn't exist."""

    def test_custom_message(self):
        """safe_get_or_raise passes custom message to exception."""
```

### 8.5 Config Tests (`tests/test_config/test_strict_config.py`) — NEW FILE

```python
class TestStrictModeConfig:
    """Test AuthzConfig strict mode fields."""

    def test_default_values(self):
        """New fields should have safe defaults (all ignore/False)."""

    def test_merge_preserves_new_fields(self):
        """merge() should handle strict_mode and per-field settings."""

    def test_strict_mode_true_applies_defaults(self):
        """strict_mode=True resolves to warn/log defaults."""

    def test_configure_accepts_new_kwargs(self):
        """configure() should accept strict_mode and related kwargs."""
```

---

## 9. Migration & Backwards Compatibility

### Zero Breaking Changes

All new config fields default to the current behavior:
- `strict_mode=False`
- `on_unprotected_get="ignore"`
- `on_text_query="ignore"`
- `on_skip_authz="ignore"`
- `audit_bypasses=False`

Existing code will behave identically. Users must explicitly opt into strict mode or individual bypass controls.

### Deprecation: None Required

No existing APIs are changed or removed.

### Recommended Adoption Path

1. **v0.x.0** — Ship new config fields, bypass handlers, safe_get, and docs. All defaults are off.
2. **v0.x.0 changelog** — Prominently call out the security model documentation.
3. **v1.0.0** — Consider changing default to `strict_mode=True` (breaking change, major version).

---

## 10. Open Questions

1. **Should `safe_get` use `can()` (in-memory SQLite) or re-query with `authorize_query()`?**
   Recommendation: Use `can()` for consistency with the existing point-check API. The in-memory approach avoids an extra DB round-trip. Tradeoff: `can()` creates a temporary SQLite engine per call (see plan 01 for optimizing this).

2. **Should `from_statement()` be detected and warned?**
   Recommendation: Yes, in a future iteration. For now, document it as a known bypass. Detection would require inspecting the statement AST for `FromStatement` nodes, which adds complexity.

3. **Should `on_unprotected_get` fire for relationship loads too?**
   Recommendation: No. Relationship loads are already protected by `with_loader_criteria()` in the interceptor. The `is_relationship_load` skip is safe because loader criteria was already applied to the parent query. Only `is_column_load` (which covers `session.get()`) is a true bypass.

4. **Thread safety of bypass logging?**
   Python's logging module is thread-safe. The `warnings` module is also thread-safe. No additional synchronization needed.
