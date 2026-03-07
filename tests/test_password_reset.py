"""
Tests for POST /auth/reset-password and POST /auth/update-password.

Run: pytest tests/test_password_reset.py -v
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

# Configure env before importing app modules
os.environ.setdefault("SUPABASE_JWT_SECRET", "test-secret-at-least-32-chars-long!!")
os.environ.setdefault("SUPABASE_URL", "http://localhost:54321")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test-service-key")
os.environ.setdefault("AUTH_MODE", "dual")

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from routes.auth_routes import router, _reset_password_calls, _update_password_calls
from middleware._compat import User, AnonymousUser

SECRET = os.environ["SUPABASE_JWT_SECRET"]
SUPABASE_URL = os.environ["SUPABASE_URL"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jwt(sub: str = "user-uuid-1234", email: str = "test@example.com") -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "email": email,
        "aud": "authenticated",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "app_metadata": {"organization_id": 1, "role": "viewer"},
        "user_metadata": {"first_name": "Test", "last_name": "User"},
    }
    return pyjwt.encode(payload, SECRET, algorithm="HS256")


def _make_app(*, authenticated: bool = False, user_sub: str = "user-uuid-1234") -> FastAPI:
    """Build a minimal FastAPI app with the auth router and fake middleware state."""
    app = FastAPI()
    app.include_router(router)

    # Inject an HTTP client placeholder (tests mock it per-test)
    app.state.http_client = None  # triggers per-request client creation in _http_client

    @app.middleware("http")
    async def _inject_user(request: Request, call_next):
        if authenticated:
            user = MagicMock()
            user.is_authenticated = True
            user.sub = user_sub
        else:
            user = AnonymousUser()
        request.state.user = user
        return await call_next(request)

    return app


# ---------------------------------------------------------------------------
# POST /auth/reset-password
# ---------------------------------------------------------------------------

class TestResetPassword:

    def setup_method(self):
        """Clear rate limiter state before each test."""
        _reset_password_calls.clear()

    def test_returns_200_for_existing_email(self):
        """Supabase succeeds → 200 with generic message."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        app = _make_app()
        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            resp = client.post("/auth/reset-password", json={"email": "user@example.com"})

        assert resp.status_code == 200
        assert "reset email" in resp.json()["message"].lower()

    def test_returns_200_for_nonexistent_email(self):
        """Supabase returns 404 → still 200 to prevent enumeration."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        app = _make_app()
        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            resp = client.post("/auth/reset-password", json={"email": "nobody@example.com"})

        assert resp.status_code == 200
        assert "reset email" in resp.json()["message"].lower()

    def test_returns_200_when_supabase_errors(self):
        """Network/Supabase error → still 200 (don't leak info)."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("network error"))

        app = _make_app()
        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            resp = client.post("/auth/reset-password", json={"email": "user@example.com"})

        assert resp.status_code == 200

    def test_invalid_email_rejected(self):
        """Malformed email → 422 validation error."""
        app = _make_app()
        client = TestClient(app)
        resp = client.post("/auth/reset-password", json={"email": "not-an-email"})
        assert resp.status_code == 422

    def test_missing_email_rejected(self):
        """Missing email field → 422."""
        app = _make_app()
        client = TestClient(app)
        resp = client.post("/auth/reset-password", json={})
        assert resp.status_code == 422

    def test_calls_supabase_recover_endpoint(self):
        """Verify the correct Supabase URL is called."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        app = _make_app()
        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            client.post("/auth/reset-password", json={"email": "user@example.com"})

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert "/auth/v1/recover" in call_args[0][0]
        assert call_args[1]["json"]["email"] == "user@example.com"


# ---------------------------------------------------------------------------
# POST /auth/update-password
# ---------------------------------------------------------------------------

class TestUpdatePassword:

    def setup_method(self):
        """Clear rate limiter state before each test."""
        _update_password_calls.clear()

    def test_unauthenticated_returns_401(self):
        """No auth → 401."""
        app = _make_app(authenticated=False)
        client = TestClient(app)
        resp = client.post("/auth/update-password", json={"new_password": "newpass123"})
        assert resp.status_code == 401

    def test_password_too_short_returns_422(self):
        """Password < 8 chars → 422."""
        app = _make_app(authenticated=True)
        token = _make_jwt()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"id": "user-uuid-1234"})

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_resp)

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            resp = client.post(
                "/auth/update-password",
                json={"new_password": "short"},
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 422
        assert "8 characters" in resp.json()["detail"]

    def test_password_exactly_8_chars_accepted(self):
        """Password of exactly 8 chars with complexity → 200."""
        app = _make_app(authenticated=True)
        token = _make_jwt()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"id": "user-uuid-1234"})

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_resp)
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            resp = client.post(
                "/auth/update-password",
                json={"new_password": "Exact8!x"},
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        assert "updated" in resp.json()["message"].lower()

    def test_successful_password_update(self):
        """Happy path: authenticated, valid password → 200."""
        app = _make_app(authenticated=True)
        token = _make_jwt()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"id": "user-uuid-1234"})

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_resp)
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            resp = client.post(
                "/auth/update-password",
                json={"new_password": "SuperSecret99"},
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        assert resp.json()["message"] == "Password updated successfully"

    def test_supabase_failure_returns_400(self):
        """Supabase returns error → 400."""
        app = _make_app(authenticated=True)
        token = _make_jwt()

        mock_resp = MagicMock()
        mock_resp.status_code = 422
        mock_resp.json = MagicMock(return_value={"message": "Password too weak"})

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_resp)
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            resp = client.post(
                "/auth/update-password",
                json={"new_password": "ValidLength1"},
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 400

    def test_calls_supabase_user_endpoint(self):
        """Verify correct Supabase PUT /auth/v1/user is called with Bearer token."""
        app = _make_app(authenticated=True)
        token = _make_jwt()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"id": "user-uuid-1234"})

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_resp)
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            client.post(
                "/auth/update-password",
                json={"new_password": "NewPassword123"},
                headers={"Authorization": f"Bearer {token}"},
            )

        mock_client.put.assert_called_once()
        call_args = mock_client.put.call_args
        assert "/auth/v1/user" in call_args[0][0]
        assert call_args[1]["json"]["password"] == "NewPassword123"
        assert f"Bearer {token}" in call_args[1]["headers"]["Authorization"]

    def test_missing_new_password_field_rejected(self):
        """Missing new_password field → 422."""
        app = _make_app(authenticated=True)
        token = _make_jwt()
        client = TestClient(app)
        resp = client.post(
            "/auth/update-password",
            json={},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422

    def test_password_no_uppercase_rejected(self):
        """Password with no uppercase → 422."""
        app = _make_app(authenticated=True)
        token = _make_jwt()
        client = TestClient(app)
        resp = client.post(
            "/auth/update-password",
            json={"new_password": "nouppercase1"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422
        assert "uppercase" in resp.json()["detail"].lower()

    def test_password_no_lowercase_rejected(self):
        """Password with no lowercase → 422."""
        app = _make_app(authenticated=True)
        token = _make_jwt()
        client = TestClient(app)
        resp = client.post(
            "/auth/update-password",
            json={"new_password": "NOLOWERCASE1"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422
        assert "lowercase" in resp.json()["detail"].lower()

    def test_password_no_number_rejected(self):
        """Password with no number → 422."""
        app = _make_app(authenticated=True)
        token = _make_jwt()
        client = TestClient(app)
        resp = client.post(
            "/auth/update-password",
            json={"new_password": "NoNumberHere"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422
        assert "number" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Rate limiting tests for new routes
# ---------------------------------------------------------------------------

class TestPasswordResetRateLimit:

    def setup_method(self):
        _reset_password_calls.clear()

    def test_reset_password_rate_limit_after_3_requests(self):
        """4th reset-password request from same IP → 429."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        app = _make_app()
        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app, raise_server_exceptions=False)
            for _ in range(3):
                r = client.post("/auth/reset-password", json={"email": "user@example.com"})
                assert r.status_code == 200

            # 4th request should be rate limited
            r = client.post("/auth/reset-password", json={"email": "user@example.com"})
            assert r.status_code == 429


class TestUpdatePasswordRateLimit:

    def setup_method(self):
        _update_password_calls.clear()

    def test_update_password_rate_limit_after_5_requests(self):
        """6th update-password request from same IP → 429."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"id": "user-uuid-1234"})

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_resp)
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        app = _make_app(authenticated=True)
        token = _make_jwt()

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app, raise_server_exceptions=False)
            for _ in range(5):
                r = client.post(
                    "/auth/update-password",
                    json={"new_password": "SuperSecret99"},
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert r.status_code == 200

            # 6th request should be rate limited
            r = client.post(
                "/auth/update-password",
                json={"new_password": "SuperSecret99"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 429
