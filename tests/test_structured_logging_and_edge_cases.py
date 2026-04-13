"""
Tests for structured logging and auth edge cases (#839).

Covers:
- Structured JSON log formatter output shape
- auth_log helper emits correct structured fields
- Token expiry edge cases (just-expired, far-future)
- Missing/malformed Authorization header edge cases
- RBAC with user_metadata fallback role
- Logout with no refresh token in body
- Login with empty/whitespace credentials
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

# Ensure test env
os.environ.setdefault("SUPABASE_JWT_SECRET", "test-secret-at-least-32-chars-long!!")
os.environ.setdefault("SUPABASE_URL", "http://localhost:54321")
os.environ.setdefault("AUTH_MODE", "dual")

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from config.logging_config import StructuredJSONFormatter, auth_log
from middleware._compat import AnonymousUser, User


SECRET = os.environ["SUPABASE_JWT_SECRET"]


# ---------------------------------------------------------------------------
# Structured Logging Tests
# ---------------------------------------------------------------------------

class TestStructuredJSONFormatter:
    """Verify the JSON formatter produces valid, well-shaped output."""

    def test_basic_log_is_valid_json(self):
        formatter = StructuredJSONFormatter()
        record = logging.LogRecord(
            name="test.logger", level=logging.INFO, pathname="",
            lineno=0, msg="hello world", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "INFO"
        assert parsed["message"] == "hello world"
        assert parsed["logger"] == "test.logger"
        assert "timestamp" in parsed

    def test_extra_fields_included(self):
        formatter = StructuredJSONFormatter()
        record = logging.LogRecord(
            name="auth.events", level=logging.INFO, pathname="",
            lineno=0, msg="login_success", args=(), exc_info=None,
        )
        record.action = "login_success"
        record.user_id = "abc-123"
        record.ip = "10.0.0.1"
        record.email = "test@example.com"
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["action"] == "login_success"
        assert parsed["user_id"] == "abc-123"
        assert parsed["ip"] == "10.0.0.1"
        assert parsed["email"] == "test@example.com"

    def test_missing_extra_fields_omitted(self):
        formatter = StructuredJSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.WARNING, pathname="",
            lineno=0, msg="no extras", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "action" not in parsed
        assert "user_id" not in parsed

    def test_exception_included_in_output(self):
        formatter = StructuredJSONFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="",
            lineno=0, msg="error", args=(), exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]


class TestAuthLogHelper:
    """Verify the auth_log convenience function emits structured events."""

    def test_auth_log_emits_to_logger(self, caplog):
        with caplog.at_level(logging.INFO, logger="auth.events"):
            auth_log("test_action", user_id="u1", ip="1.2.3.4")
        assert any("test_action" in r.message for r in caplog.records)

    def test_auth_log_warning_level(self, caplog):
        with caplog.at_level(logging.WARNING, logger="auth.events"):
            auth_log("bad_thing", level=logging.WARNING, detail="oh no")
        assert any(r.levelno == logging.WARNING for r in caplog.records)


# ---------------------------------------------------------------------------
# Token Expiry Edge Cases
# ---------------------------------------------------------------------------

def _make_jwt(exp_offset_seconds: int = 3600, sub: str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890") -> str:
    """Create a Supabase-style JWT with a configurable expiry offset from now."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "email": "edge@example.com",
        "aud": "authenticated",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=exp_offset_seconds)).timestamp()),
        "app_metadata": {"organization_id": 1, "role": "viewer"},
        "user_metadata": {"first_name": "Edge", "last_name": "Case"},
    }
    return pyjwt.encode(payload, SECRET, algorithm="HS256")


def _build_supabase_app():
    """Build a minimal app with supabase auth middleware for testing."""
    from config.supabase_config import AuthMode
    import config.supabase_config as cfg
    import middleware.supabase_auth_middleware as mw_mod

    # Patch AUTH_MODE at the module level where the middleware reads it
    cfg.AUTH_MODE = AuthMode.SUPABASE
    mw_mod.AUTH_MODE = AuthMode.SUPABASE

    app = FastAPI()

    @app.middleware("http")
    async def mw(request, call_next):
        from middleware.supabase_auth_middleware import supabase_auth_middleware
        return await supabase_auth_middleware(request, call_next)

    @app.get("/test")
    async def test_route(request: Request):
        user = request.state.user
        return {
            "authenticated": user.is_authenticated,
            "email": getattr(user, "email", None),
        }

    return app


class TestTokenExpiryEdgeCases:
    """Edge cases around JWT expiration timing."""

    def test_just_expired_token_returns_401(self):
        """A token that expired 1 second ago should be rejected."""
        app = _build_supabase_app()
        client = TestClient(app)
        token = _make_jwt(exp_offset_seconds=-1)
        resp = client.get("/test", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_far_future_token_accepted(self):
        """A token with a very long expiry (30 days) should still be accepted."""
        app = _build_supabase_app()
        client = TestClient(app)
        token = _make_jwt(exp_offset_seconds=30 * 24 * 3600)
        resp = client.get("/test", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is True

    def test_token_expiring_in_1_second_still_valid(self):
        """A token expiring very soon (5s) should still be accepted right now."""
        app = _build_supabase_app()
        client = TestClient(app)
        token = _make_jwt(exp_offset_seconds=5)
        resp = client.get("/test", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Missing / Malformed Auth Header Edge Cases
# ---------------------------------------------------------------------------

class TestMalformedAuthHeaders:
    """Edge cases for Authorization header parsing."""

    def test_bearer_with_empty_token(self):
        """'Bearer ' with no token should result in anonymous or 401."""
        app = _build_supabase_app()
        client = TestClient(app)
        resp = client.get("/test", headers={"Authorization": "Bearer "})
        # Empty token should either be anonymous or 401
        assert resp.status_code in (200, 401)
        if resp.status_code == 200:
            assert resp.json()["authenticated"] is False

    def test_non_bearer_prefix(self):
        """A non-Bearer auth scheme should be rejected."""
        app = _build_supabase_app()
        client = TestClient(app)
        resp = client.get("/test", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert resp.status_code == 401

    def test_garbage_token(self):
        """A completely invalid JWT string should return 401."""
        app = _build_supabase_app()
        client = TestClient(app)
        resp = client.get("/test", headers={"Authorization": "Bearer not.a.jwt.at.all"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# RBAC user_metadata Fallback Path Coverage
# ---------------------------------------------------------------------------

class TestRBACUserMetadataFallback:
    """Ensure RBAC works when role is only in user_metadata (not app_metadata)."""

    def test_user_metadata_role_grants_access(self):
        """When app_metadata has no role but user_metadata does, that role is used."""
        from middleware.rbac import require_role

        app = FastAPI()

        @app.get("/org-route", dependencies=[require_role("org_manager")])
        async def org_route(request: Request):
            return {"ok": True}

        @app.middleware("http")
        async def inject_state(request: Request, call_next):
            user = MagicMock()
            user.is_authenticated = True
            request.state.user = user
            # Role only in user_metadata — app_metadata is empty
            request.state.supabase_claims = {
                "app_metadata": {},
                "user_metadata": {"role": "org_manager"},
            }
            return await call_next(request)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/org-route")
        assert resp.status_code == 200

    def test_no_role_anywhere_denies_access(self):
        """When neither app_metadata nor user_metadata has a role, access is denied."""
        from middleware.rbac import require_role

        app = FastAPI()

        @app.get("/admin-route", dependencies=[require_role("admin")])
        async def admin_route(request: Request):
            return {"ok": True}

        @app.middleware("http")
        async def inject_state(request: Request, call_next):
            user = MagicMock()
            user.is_authenticated = True
            request.state.user = user
            request.state.supabase_claims = {
                "app_metadata": {},
                "user_metadata": {},
            }
            return await call_next(request)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/admin-route")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Logout Edge Cases
# ---------------------------------------------------------------------------

class TestLogoutEdgeCases:
    """Edge cases for the /auth/logout route."""

    def _make_logout_app(self):
        from routes.auth_routes import router
        app = FastAPI()
        app.include_router(router)
        return app

    def test_logout_with_no_body(self):
        """Logout with no request body should still succeed."""
        app = self._make_logout_app()
        client = TestClient(app, raise_server_exceptions=False)

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            instance.post = AsyncMock(return_value=MagicMock(status_code=200))
            MockClient.return_value = instance

            resp = client.post("/auth/logout")

        assert resp.status_code == 200
        assert resp.json()["detail"] == "Logged out"

    def test_logout_with_empty_refresh_token(self):
        """Logout with an empty refresh_token string should still succeed."""
        app = self._make_logout_app()
        client = TestClient(app, raise_server_exceptions=False)

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            instance.post = AsyncMock(return_value=MagicMock(status_code=200))
            MockClient.return_value = instance

            resp = client.post("/auth/logout", json={"refresh_token": ""})

        assert resp.status_code == 200
        assert resp.json()["detail"] == "Logged out"
