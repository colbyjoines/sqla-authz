"""Tests for FastAPI error handlers."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sqla_authz.exceptions import AuthorizationDenied, NoPolicyError
from sqla_authz.integrations.fastapi._errors import install_error_handlers


@pytest.fixture()
def app() -> FastAPI:
    """Create a minimal FastAPI app with error handlers installed."""
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/denied")
    async def trigger_denied() -> None:
        raise AuthorizationDenied(
            actor="user-1",
            action="delete",
            resource_type="Post",
        )

    @app.get("/no-policy")
    async def trigger_no_policy() -> None:
        raise NoPolicyError(resource_type="Post", action="delete")

    return app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


class TestAuthorizationDeniedHandler:
    def test_returns_403(self, client: TestClient) -> None:
        response = client.get("/denied")
        assert response.status_code == 403

    def test_response_is_json(self, client: TestClient) -> None:
        response = client.get("/denied")
        assert response.headers["content-type"] == "application/json"

    def test_response_has_detail(self, client: TestClient) -> None:
        response = client.get("/denied")
        body = response.json()
        assert "detail" in body
        assert "not authorized" in body["detail"].lower()


class TestNoPolicyHandler:
    def test_returns_500(self, client: TestClient) -> None:
        response = client.get("/no-policy")
        assert response.status_code == 500

    def test_response_is_json(self, client: TestClient) -> None:
        response = client.get("/no-policy")
        assert response.headers["content-type"] == "application/json"

    def test_response_has_detail(self, client: TestClient) -> None:
        response = client.get("/no-policy")
        body = response.json()
        assert "detail" in body
        assert "no policy" in body["detail"].lower()
