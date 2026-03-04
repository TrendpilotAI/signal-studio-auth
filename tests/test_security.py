"""
Tests for security fixes:
  - TODO-351: Hardcoded/empty JWT secret fallbacks
  - TODO-352: Rate limiting on /auth/login and /auth/signup
"""

from __future__ import annotations

import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI


# ---------------------------------------------------------------------------
# TODO-351: JWT secret validation tests
# ---------------------------------------------------------------------------

class TestJwtSecretValidation:
    """config._require_secret() must reject weak/missing secrets outside pytest."""

    def test_empty_secret_raises_in_production(self, monkeypatch):
        """An empty AUTH_SECRET_KEY should raise RuntimeError in prod mode."""
        monkeypatch.delenv("AUTH_SECRET_KEY", raising=False)
        monkeypatch.setenv("PYTEST_CURRENT_TEST", "")  # clear pytest marker

        # Patch _TESTING to False to simulate production
        import importlib
        import config.supabase_config as cfg
        original = cfg._TESTING
        try:
            cfg._TESTING = False
            with pytest.raises(RuntimeError, match="missing or set to an insecure default"):
                cfg._require_secret("AUTH_SECRET_KEY")
        finally:
            cfg._TESTING = original

    def test_known_weak_secret_raises_in_production(self, monkeypatch):
        """'very_secure_secret' default must be rejected in production."""
        monkeypatch.setenv("AUTH_SECRET_KEY", "very_secure_secret")

        import config.supabase_config as cfg
        original = cfg._TESTING
        try:
            cfg._TESTING = False
            with pytest.raises(RuntimeError, match="insecure default"):
                cfg._require_secret("AUTH_SECRET_KEY")
        finally:
            cfg._TESTING = original

    def test_short_secret_raises_in_production(self, monkeypatch):
        """Secrets under 32 chars must be rejected in production."""
        monkeypatch.setenv("AUTH_SECRET_KEY", "tooshort")

        import config.supabase_config as cfg
        original = cfg._TESTING
        try:
            cfg._TESTING = False
            with pytest.raises(RuntimeError, match="too short"):
                cfg._require_secret("AUTH_SECRET_KEY")
        finally:
            cfg._TESTING = original

    def test_strong_secret_accepted(self, monkeypatch):
        """A 64-char random secret should be accepted."""
        strong = "a" * 64
        monkeypatch.setenv("AUTH_SECRET_KEY", strong)

        import config.supabase_config as cfg
        original = cfg._TESTING
        try:
            cfg._TESTING = False
            result = cfg._require_secret("AUTH_SECRET_KEY")
            assert result == strong
        finally:
            cfg._TESTING = original

    def test_weak_secret_allowed_in_tests(self, monkeypatch):
        """During pytest runs, weak secrets should not raise (CI/CD safety)."""
        monkeypatch.setenv("AUTH_SECRET_KEY", "very_secure_secret")

        import config.supabase_config as cfg
        # _TESTING should be True here (we're inside pytest)
        assert cfg._TESTING is True
        # Should not raise
        result = cfg._require_secret("AUTH_SECRET_KEY")
        assert result == "very_secure_secret"


# ---------------------------------------------------------------------------
# TODO-352: Rate limiting tests
# ---------------------------------------------------------------------------

def _make_test_app():
    """Build a minimal FastAPI app with auth routes for testing."""
    from routes.auth_routes import router, _login_limiter, _signup_limiter
    # Reset limiters so tests are independent
    _login_limiter._calls.clear()
    _signup_limiter._calls.clear()

    app = FastAPI()
    app.include_router(router)
    return app


class TestRateLimiting:
    """Rate limiter on /auth/login and /auth/signup."""

    def test_login_rate_limit_enforced(self, monkeypatch):
        """6th login attempt within 60s should return 429."""
        app = _make_test_app()
        client = TestClient(app, raise_server_exceptions=False)

        payload = {"email": "test@example.com", "password": "pw"}

        # Mock httpx so we don't hit Supabase
        async def _mock_post(*args, **kwargs):
            m = MagicMock()
            m.status_code = 400
            m.json.return_value = {"error": "invalid_grant"}
            return m

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            instance.post = _mock_post
            MockClient.return_value = instance

            responses = [client.post("/auth/login", json=payload) for _ in range(6)]

        # First 5 should not be rate-limited (may fail auth but not 429)
        for r in responses[:5]:
            assert r.status_code != 429, f"Expected no rate limit on attempt, got 429"
        # 6th should be rate-limited
        assert responses[5].status_code == 429

    def test_signup_rate_limit_enforced(self):
        """4th signup attempt within 60s should return 429."""
        app = _make_test_app()
        client = TestClient(app, raise_server_exceptions=False)

        payload = {
            "email": "new@example.com",
            "password": "Password123!",
            "first_name": "Test",
            "last_name": "User",
        }

        async def _mock_post(*args, **kwargs):
            m = MagicMock()
            m.status_code = 400
            m.json.return_value = {"error": "email_taken"}
            return m

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            instance.post = _mock_post
            MockClient.return_value = instance

            responses = [client.post("/auth/signup", json=payload) for _ in range(4)]

        for r in responses[:3]:
            assert r.status_code != 429
        assert responses[3].status_code == 429

    def test_rate_limit_response_has_retry_after_header(self):
        """429 response must include Retry-After header."""
        from routes.auth_routes import _login_limiter

        # Exhaust the limit for a specific IP
        fake_ip = "10.0.0.42"
        for _ in range(5):
            _login_limiter._calls[fake_ip].append(__import__("time").monotonic())

        app = _make_test_app()
        # Re-add the exhausted state (make_test_app clears it)
        from routes.auth_routes import _login_limiter as lim
        import time
        for _ in range(5):
            lim._calls[fake_ip].append(time.monotonic())

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/auth/login",
            json={"email": "x@y.com", "password": "p"},
            headers={"X-Forwarded-For": fake_ip},
        )
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers

    def test_different_ips_have_independent_limits(self):
        """Rate limit is per-IP — one IP exhausted shouldn't block others."""
        from routes.auth_routes import _login_limiter
        import time

        app = _make_test_app()
        from routes.auth_routes import _login_limiter as lim
        # Exhaust IP A
        for _ in range(5):
            lim._calls["1.2.3.4"].append(time.monotonic())

        client = TestClient(app, raise_server_exceptions=False)

        async def _mock_post(*args, **kwargs):
            m = MagicMock()
            m.status_code = 400
            m.json.return_value = {}
            return m

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            instance.post = _mock_post
            MockClient.return_value = instance

            # IP A is exhausted
            resp_a = client.post(
                "/auth/login",
                json={"email": "a@a.com", "password": "pw"},
                headers={"X-Forwarded-For": "1.2.3.4"},
            )
            # IP B is fresh
            resp_b = client.post(
                "/auth/login",
                json={"email": "b@b.com", "password": "pw"},
                headers={"X-Forwarded-For": "5.6.7.8"},
            )

        assert resp_a.status_code == 429
        assert resp_b.status_code != 429


# ---------------------------------------------------------------------------
# TODO-353: Admin role check on /invite-to-org
# ---------------------------------------------------------------------------

class TestInviteToOrgAdminCheck:
    """
    /auth/invite-to-org must only be accessible to admin-role users.
    Authenticated non-admins should get 403 Forbidden.
    Unauthenticated callers should get 401.
    """

    def _make_app_with_user(self, is_authenticated: bool, role: str | None):
        """Build a test FastAPI app with a stubbed auth state."""
        from fastapi import FastAPI, Request
        from fastapi.testclient import TestClient
        from routes.auth_routes import router

        app = FastAPI()
        app.include_router(router)

        @app.middleware("http")
        async def _inject_user(request: Request, call_next):
            if not is_authenticated:
                # Mimic AnonymousUser by not setting state.user
                pass
            else:
                class _FakeUser:
                    is_authenticated = True
                request.state.user = _FakeUser()
                if role is not None:
                    request.state.supabase_claims = {
                        "app_metadata": {"role": role}
                    }
                else:
                    request.state.supabase_claims = {}
            return await call_next(request)

        return app

    def test_unauthenticated_returns_401(self):
        """No user → 401."""
        app = self._make_app_with_user(is_authenticated=False, role=None)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/auth/invite-to-org",
            json={"email": "new@example.com", "organization_id": 1, "role": "viewer"},
        )
        assert resp.status_code == 401

    def test_authenticated_viewer_returns_403(self):
        """Authenticated but role=viewer → 403 Forbidden."""
        app = self._make_app_with_user(is_authenticated=True, role="viewer")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/auth/invite-to-org",
            json={"email": "new@example.com", "organization_id": 1, "role": "viewer"},
        )
        assert resp.status_code == 403
        assert "Admin role required" in resp.json().get("detail", "")

    def test_authenticated_analyst_returns_403(self):
        """Authenticated but role=analyst → 403 Forbidden."""
        app = self._make_app_with_user(is_authenticated=True, role="analyst")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/auth/invite-to-org",
            json={"email": "new@example.com", "organization_id": 1, "role": "analyst"},
        )
        assert resp.status_code == 403

    def test_no_role_in_claims_returns_403(self):
        """Authenticated with no role field in claims → 403 Forbidden (default deny)."""
        app = self._make_app_with_user(is_authenticated=True, role=None)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/auth/invite-to-org",
            json={"email": "new@example.com", "organization_id": 1},
        )
        assert resp.status_code == 403

    def test_admin_role_proceeds_to_supabase(self):
        """Authenticated with role=admin → passes the role check, hits Supabase."""
        from unittest.mock import AsyncMock, patch, MagicMock

        app = self._make_app_with_user(is_authenticated=True, role="admin")
        client = TestClient(app, raise_server_exceptions=False)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": "uuid-123", "action_link": "https://..."}

        async def _mock_post(*args, **kwargs):
            return mock_resp

        async def _mock_put(*args, **kwargs):
            return mock_resp

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            instance.post = _mock_post
            instance.put = _mock_put
            MockClient.return_value = instance

            resp = client.post(
                "/auth/invite-to-org",
                json={"email": "new@example.com", "organization_id": 1, "role": "viewer"},
            )

        # Should pass the role check and return 200 from Supabase mock
        assert resp.status_code == 200
        assert resp.json().get("detail") == "Invitation sent"
