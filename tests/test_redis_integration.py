"""
Redis integration tests for signal-studio-auth (TODO-601).

Uses fakeredis to provide a real in-process Redis implementation, giving
true Redis round-trip semantics without an external server.

Test coverage:
  - /auth/refresh: valid token → new token issued, old consumed
  - /auth/refresh: consumed/rotated token → 401
  - /auth/refresh: fabricated token → 401
  - /auth/logout: token revoked in Redis, subsequent refresh fails
  - /auth/invite-to-org: analyst role → 403, viewer role → 403, admin → success
  - Rate limiting: 6th login request in window → 429, 4th signup → 429

Run: pytest tests/test_redis_integration.py -v
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import pytest

# ---------------------------------------------------------------------------
# Environment bootstrap (must be before any local imports)
# ---------------------------------------------------------------------------
os.environ.setdefault("SUPABASE_JWT_SECRET", "test-secret-at-least-32-chars-long!!")
os.environ.setdefault("SUPABASE_URL", "http://localhost:54321")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test-service-key")
os.environ.setdefault("AUTH_MODE", "supabase")

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _fake_redis() -> fakeredis.FakeRedis:
    """Return a fresh in-process FakeRedis instance."""
    return fakeredis.FakeRedis()


def _build_test_app():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes.auth_routes import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


def _make_supabase_token_response(access: str = "new.access.jwt",
                                   refresh: str = "new-supabase-rt") -> dict:
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": 3600,
    }


def _mock_supabase_post(response_body: dict, status_code: int = 200):
    """Return a patchable AsyncMock for httpx.AsyncClient.post."""
    mock_http = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = response_body
    mock_http.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
    return mock_http


# ---------------------------------------------------------------------------
# TestRefreshTokenRotation
# ---------------------------------------------------------------------------

class TestRefreshTokenRotation:
    """
    /auth/refresh Redis round-trip tests.

    fakeredis is patched in as the get_redis() return value so all
    SETEX / GETDEL operations use real Redis semantics.
    """

    def test_valid_token_issues_new_token_and_consumes_old(self):
        """POST /auth/refresh with valid opaque token → new access+refresh tokens returned."""
        from routes.auth_routes import REFRESH_TOKEN_PREFIX

        redis = _fake_redis()
        opaque = str(uuid.uuid4())
        supabase_rt = "supabase-rt-original"
        # Pre-seed the opaque → supabase RT mapping
        redis.setex(f"{REFRESH_TOKEN_PREFIX}{opaque}", 60, supabase_rt)

        new_response = _make_supabase_token_response()
        client = _build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("httpx.AsyncClient", _mock_supabase_post(new_response)):
                resp = client.post("/auth/refresh", json={"refresh_token": opaque})

        assert resp.status_code == 200
        data = resp.json()
        # New access token from Supabase must be returned
        assert data["access_token"] == "new.access.jwt"
        # Returned refresh token must be a NEW opaque UUID (not the Supabase one)
        new_opaque = data["refresh_token"]
        assert new_opaque != supabase_rt
        uuid.UUID(new_opaque, version=4)  # must be valid UUID4
        # Old token must be consumed (deleted from Redis)
        assert redis.get(f"{REFRESH_TOKEN_PREFIX}{opaque}") is None
        # New opaque token must be stored in Redis
        assert redis.get(f"{REFRESH_TOKEN_PREFIX}{new_opaque}") is not None

    def test_consumed_token_returns_401(self):
        """POST /auth/refresh with already-rotated (consumed) token → 401."""
        from routes.auth_routes import REFRESH_TOKEN_PREFIX

        redis = _fake_redis()
        opaque = str(uuid.uuid4())
        redis.setex(f"{REFRESH_TOKEN_PREFIX}{opaque}", 60, "supabase-rt-once")

        new_response = _make_supabase_token_response()
        client = _build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("httpx.AsyncClient", _mock_supabase_post(new_response)):
                # First use — should succeed
                resp1 = client.post("/auth/refresh", json={"refresh_token": opaque})
                # Second use of the SAME original opaque token — already consumed
                resp2 = client.post("/auth/refresh", json={"refresh_token": opaque})

        assert resp1.status_code == 200
        assert resp2.status_code == 401
        detail = resp2.json()["detail"].lower()
        assert "expired" in detail or "invalid" in detail

    def test_fabricated_token_returns_401(self):
        """POST /auth/refresh with completely unknown token → 401."""
        redis = _fake_redis()  # empty — token not seeded
        client = _build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            resp = client.post(
                "/auth/refresh",
                json={"refresh_token": str(uuid.uuid4())},
            )

        assert resp.status_code == 401
        detail = resp.json()["detail"].lower()
        assert "expired" in detail or "invalid" in detail


# ---------------------------------------------------------------------------
# TestLogoutRevocation
# ---------------------------------------------------------------------------

class TestLogoutRevocation:
    """
    /auth/logout revocation: token removed from Redis, subsequent refresh fails.
    """

    def test_logout_revokes_token_in_redis(self):
        """POST /auth/logout removes the opaque token from Redis."""
        from routes.auth_routes import REFRESH_TOKEN_PREFIX

        redis = _fake_redis()
        opaque = str(uuid.uuid4())
        redis.setex(f"{REFRESH_TOKEN_PREFIX}{opaque}", 60, "supabase-rt-logout")

        logout_mock = MagicMock()
        logout_resp = MagicMock()
        logout_resp.status_code = 204
        logout_mock.return_value.__aenter__.return_value.post = AsyncMock(return_value=logout_resp)

        client = _build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("httpx.AsyncClient", logout_mock):
                resp = client.post(
                    "/auth/logout",
                    json={"refresh_token": opaque},
                    headers={"Authorization": "Bearer fake.jwt"},
                )

        assert resp.status_code == 200
        assert resp.json()["detail"] == "Logged out"
        # Token must be gone from Redis
        assert redis.get(f"{REFRESH_TOKEN_PREFIX}{opaque}") is None

    def test_revoked_token_cannot_refresh(self):
        """After logout, the same token must be rejected by /auth/refresh (401)."""
        from routes.auth_routes import REFRESH_TOKEN_PREFIX

        redis = _fake_redis()
        opaque = str(uuid.uuid4())
        redis.setex(f"{REFRESH_TOKEN_PREFIX}{opaque}", 60, "supabase-rt-to-revoke")

        logout_resp = MagicMock()
        logout_resp.status_code = 204
        http_mock = MagicMock()
        http_mock.return_value.__aenter__.return_value.post = AsyncMock(return_value=logout_resp)

        client = _build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("httpx.AsyncClient", http_mock):
                # Logout first
                client.post(
                    "/auth/logout",
                    json={"refresh_token": opaque},
                    headers={"Authorization": "Bearer fake.jwt"},
                )
                # Attempt refresh with the now-revoked token
                resp = client.post("/auth/refresh", json={"refresh_token": opaque})

        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TestInviteToOrgRBAC
# ---------------------------------------------------------------------------

class TestInviteToOrgRBAC:
    """
    /auth/invite-to-org RBAC enforcement.

    The route inspects request.state.user and request.state.supabase_claims.
    We inject those via a custom middleware on a fresh app instance.
    """

    def _build_app_with_role(self, role: str | None, authenticated: bool = True):
        """Build a TestClient that injects the given role into request state."""
        from fastapi import FastAPI, Request
        from fastapi.testclient import TestClient
        from routes.auth_routes import router

        app = FastAPI()

        @app.middleware("http")
        async def inject_auth(request: Request, call_next):
            user = MagicMock()
            user.is_authenticated = authenticated
            request.state.user = user
            if role:
                request.state.supabase_claims = {"app_metadata": {"role": role}}
            else:
                request.state.supabase_claims = None
            return await call_next(request)

        app.include_router(router)
        return TestClient(app, raise_server_exceptions=False)

    def _invite_payload(self) -> dict:
        return {
            "email": "newuser@example.com",
            "organization_id": 123,
            "role": "viewer",
        }

    def test_analyst_role_returns_403(self):
        """Analyst attempting to invite → 403 Forbidden."""
        client = self._build_app_with_role("analyst")
        resp = client.post("/auth/invite-to-org", json=self._invite_payload())
        assert resp.status_code == 403
        assert "Admin role required" in resp.json()["detail"]

    def test_viewer_role_returns_403(self):
        """Viewer attempting to invite → 403 Forbidden."""
        client = self._build_app_with_role("viewer")
        resp = client.post("/auth/invite-to-org", json=self._invite_payload())
        assert resp.status_code == 403
        assert "Admin role required" in resp.json()["detail"]

    def test_admin_role_succeeds(self):
        """Admin role → invite call reaches Supabase and succeeds."""
        client = self._build_app_with_role("admin")

        # Mock Supabase admin API: generate_link + update user
        invite_resp = MagicMock()
        invite_resp.status_code = 200
        invite_resp.json.return_value = {
            "id": "new-user-uuid",
            "action_link": "https://supabase/invite/link",
        }

        update_resp = MagicMock()
        update_resp.status_code = 200
        update_resp.json.return_value = {"id": "new-user-uuid"}

        http_mock = MagicMock()
        http_mock.return_value.__aenter__.return_value.post = AsyncMock(return_value=invite_resp)
        http_mock.return_value.__aenter__.return_value.put = AsyncMock(return_value=update_resp)

        with patch("httpx.AsyncClient", http_mock):
            resp = client.post("/auth/invite-to-org", json=self._invite_payload())

        # Admin gets through RBAC — Supabase returned 200 so we expect success
        assert resp.status_code == 200

    def test_unauthenticated_returns_401(self):
        """No authenticated user → 401."""
        client = self._build_app_with_role(None, authenticated=False)
        resp = client.post("/auth/invite-to-org", json=self._invite_payload())
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TestRateLimiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    """
    Rate limit enforcement using the in-memory fallback (get_redis → None).

    Login  limit: 5 per 60s  → 6th request → 429
    Signup limit: 3 per 60s  → 4th request → 429
    """

    def _clear_limiters(self):
        """Reset in-memory rate limit counters between tests."""
        from routes.auth_routes import _login_calls, _signup_calls
        _login_calls.clear()
        _signup_calls.clear()

    def _build_test_app(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from routes.auth_routes import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app, raise_server_exceptions=False)

    def _supabase_ok_mock(self):
        """A Supabase mock that always returns 200 with a valid auth response."""
        return _mock_supabase_post(
            _make_supabase_token_response(),
            status_code=200,
        )

    def test_6th_login_request_returns_429(self):
        """Login allows 5 requests then rejects the 6th with HTTP 429."""
        self._clear_limiters()
        client = self._build_test_app()
        redis = _fake_redis()  # unused but keeps get_redis returning None cleanly

        with patch("routes.auth_routes.get_redis", return_value=None):
            with patch("httpx.AsyncClient", self._supabase_ok_mock()):
                responses = []
                for _ in range(6):
                    resp = client.post(
                        "/auth/login",
                        json={"email": "user@example.com", "password": "pass"},
                    )
                    responses.append(resp.status_code)

        # First 5 should succeed (200), 6th should be rate-limited (429)
        assert all(s == 200 for s in responses[:5]), f"Expected 5×200, got: {responses[:5]}"
        assert responses[5] == 429, f"Expected 429 on 6th, got: {responses[5]}"

    def test_4th_signup_request_returns_429(self):
        """Signup allows 3 requests then rejects the 4th with HTTP 429."""
        self._clear_limiters()
        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=None):
            with patch("httpx.AsyncClient", self._supabase_ok_mock()):
                responses = []
                for i in range(4):
                    resp = client.post(
                        "/auth/signup",
                        json={
                            "email": f"new{i}@example.com",
                            "password": "Password1!",
                            "first_name": "Test",
                            "last_name": "User",
                        },
                    )
                    responses.append(resp.status_code)

        # First 3 succeed, 4th is rate-limited
        assert all(s == 200 for s in responses[:3]), f"Expected 3×200, got: {responses[:3]}"
        assert responses[3] == 429, f"Expected 429 on 4th, got: {responses[3]}"

    def test_different_ips_have_independent_rate_limits(self):
        """Rate limit buckets are per-IP; different IPs should not share quotas."""
        self._clear_limiters()
        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=None):
            with patch("httpx.AsyncClient", self._supabase_ok_mock()):
                # Exhaust IP 1
                for _ in range(5):
                    client.post(
                        "/auth/login",
                        json={"email": "a@example.com", "password": "p"},
                        headers={"X-Forwarded-For": "1.1.1.1"},
                    )

                # IP 2 should still have full budget
                resp = client.post(
                    "/auth/login",
                    json={"email": "b@example.com", "password": "p"},
                    headers={"X-Forwarded-For": "2.2.2.2"},
                )

        assert resp.status_code == 200, f"Different IP should not be rate-limited, got {resp.status_code}"
