"""Exception handlers for FastAPI integration."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from sqla_authz.exceptions import AuthorizationDenied, NoPolicyError

__all__ = ["install_error_handlers"]


def install_error_handlers(app: FastAPI) -> None:
    """Install exception handlers for sqla-authz errors on a FastAPI app.

    Converts authorization exceptions into proper HTTP responses:

    - ``AuthorizationDenied`` -> 403 Forbidden
    - ``NoPolicyError`` -> 500 Internal Server Error

    Args:
        app: The FastAPI application instance.

    Example::

        from fastapi import FastAPI
        from sqla_authz.integrations.fastapi import install_error_handlers

        app = FastAPI()
        install_error_handlers(app)
    """

    @app.exception_handler(AuthorizationDenied)
    async def authz_denied_handler(  # pyright: ignore[reportUnusedFunction]
        request: object, exc: AuthorizationDenied
    ) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={"detail": str(exc)},
        )

    @app.exception_handler(NoPolicyError)
    async def no_policy_handler(  # pyright: ignore[reportUnusedFunction]
        request: object, exc: NoPolicyError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={"detail": str(exc)},
        )
