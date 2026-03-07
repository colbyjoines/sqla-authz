"""Tests for the FastAPI integration imports."""

from __future__ import annotations


class TestImportGuard:
    def test_import_succeeds(self) -> None:
        """Importing the integration works."""
        from sqla_authz.integrations.fastapi import (
            AuthzDep,
            configure_authz,
            install_error_handlers,
        )

        assert AuthzDep is not None
        assert configure_authz is not None
        assert install_error_handlers is not None
