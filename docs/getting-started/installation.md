# Installation

## Requirements

- Python 3.10+
- SQLAlchemy 2.0+

sqla-authz has no external server dependencies. It runs entirely in-process and generates SQL filter expressions that your existing SQLAlchemy session executes.

## Basic Install

=== "pip"

    ```bash
    pip install sqla-authz
    ```

=== "uv"

    ```bash
    uv add sqla-authz
    ```

## Optional Extras

Install extras alongside the core package to enable integrations and tooling.

| Extra | Installs | Use when |
|---|---|---|
| `sqla-authz[fastapi]` | `fastapi`, `httpx` | Building FastAPI apps with dependency injection |
| `sqla-authz[flask]` | `flask>=3.0` | Building Flask apps with the Flask extension |
| `sqla-authz[testing]` | `pytest`, `pytest-asyncio`, `aiosqlite` | Writing tests with built-in fixtures and assertions |
| `sqla-authz[all]` | FastAPI + Flask | Multi-framework projects |
| `sqla-authz[dev]` | All of the above + `pyright`, `ruff`, `hypothesis`, `pytest-benchmark` | Contributing to sqla-authz |

=== "pip"

    ```bash
    # FastAPI integration
    pip install sqla-authz[fastapi]

    # Flask integration
    pip install sqla-authz[flask]

    # Test utilities
    pip install sqla-authz[testing]

    # FastAPI + Flask
    pip install sqla-authz[all]
    ```

=== "uv"

    ```bash
    # FastAPI integration
    uv add sqla-authz[fastapi]

    # Flask integration
    uv add sqla-authz[flask]

    # Test utilities
    uv add sqla-authz[testing]

    # FastAPI + Flask
    uv add sqla-authz[all]
    ```

## Verify Installation

```python
import sqla_authz
print(sqla_authz.__version__)
```

Or from the command line:

```bash
python -c "import sqla_authz; print(sqla_authz.__version__)"
```

!!! tip "SQLAlchemy Version"
    sqla-authz targets the SQLAlchemy 2.0 API exclusively. The legacy 1.x `Query` API is not supported. If you are on SQLAlchemy 1.x, see the [migration guide](../migration/from-oso.md) for upgrade notes.
