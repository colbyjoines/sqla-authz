"""Tests for the FastAPI import guard."""

from __future__ import annotations

import sys
from unittest import mock


class TestImportGuard:
    def test_import_error_without_fastapi(self) -> None:
        """Importing the integration without fastapi raises ImportError."""
        # Remove any cached module
        mods_to_remove = [
            key for key in sys.modules if key.startswith("sqla_authz.integrations.fastapi")
        ]
        for mod in mods_to_remove:
            del sys.modules[mod]

        # Block fastapi import
        with mock.patch.dict(sys.modules, {"fastapi": None}):
            import importlib

            with mock.patch.dict(sys.modules):
                # Clear cached integration modules so they re-import
                for mod in mods_to_remove:
                    sys.modules.pop(mod, None)

                try:
                    import sqla_authz.integrations.fastapi as _  # noqa: F811

                    # If no error, force reimport
                    importlib.reload(_)
                    raise AssertionError("Expected ImportError")  # pragma: no cover
                except ImportError as exc:
                    assert "fastapi" in str(exc).lower()
                    assert "pip install" in str(exc).lower()

    def test_import_succeeds_with_fastapi(self) -> None:
        """Importing the integration with fastapi works fine."""
        from sqla_authz.integrations.fastapi import (
            AuthzDep,
            configure_authz,
            install_error_handlers,
        )

        assert AuthzDep is not None
        assert configure_authz is not None
        assert install_error_handlers is not None
