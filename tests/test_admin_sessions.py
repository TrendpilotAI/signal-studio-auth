"""
Tests for SSA-836 — DELETE /auth/admin/users/{user_id}/sessions.

Admin-only endpoint that revokes all of a target user's outstanding opaque
refresh tokens (Redis, reusing the CRIT-5 SCAN helper) and forces Supabase
to invalidate that user's sessions via the admin logout endpoint.

Run: pytest tests/test_admin_sessions.py -v
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
    return fakeredis.FakeRedis(decode_responses=True)


def _build_app_with_role(role: str | None, authenticated: bool = True):
    """
    Build a TestClient that injects an authenticated caller with the given
    role into request state — mirrors the pattern used for /invite-to-org
    RBAC tests in tests/test_security.py / tests/test_redis_integration.py.
    """
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


def _seed_token(redis, token_id: str, user_id: str, family_id: str | None = None) -> str:
    fid = family_id or str(uuid.uuid4())
    redis.hset(f"rt:{token_id}", mapping={
        "user_id": user_id,
        "family_id": fid,
        "parent_id": "",
        "supabase_token": f"sb-{token_id}",
        "consumed": "0",
    })
    redis.sadd(f"rt:family:{fid}", token_id)
    return fid


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------

class TestAdminRevokeSessionsRBAC:
    """DELETE /auth/admin/users/{user_id}/sessions is admin-only."""

    def test_unauthenticated_returns_401(self):
        client = _build_app_with_role(None, authenticated=False)
        resp = client.delete("/auth/admin/users/target-user-id/sessions")
        assert resp.status_code == 401

    def test_viewer_role_returns_403(self):
        client = _build_app_with_role("viewer")
        resp = client.delete("/auth/admin/users/target-user-id/sessions")
        assert resp.status_code == 403
        assert "admin" in resp.json()["detail"].lower()

    def test_analyst_role_returns_403(self):
        client = _build_app_with_role("analyst")
        resp = client.delete("/auth/admin/users/target-user-id/sessions")
        assert resp.status_code == 403

    def test_no_role_in_claims_returns_403(self):
        client = _build_app_with_role(None, authenticated=True)
        resp = client.delete("/auth/admin/users/target-user-id/sessions")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------

class TestAdminRevokeSessionsSuccess:
    """Admin caller: target user's opaque tokens are revoked; others untouched."""

    def test_admin_revokes_target_user_tokens_and_calls_supabase_logout(self):
        redis = _fake_redis()
        target_user = "target-user-uuid"

        token_a = str(uuid.uuid4())
        token_b = str(uuid.uuid4())
        family_id = _seed_token(redis, token_a, target_user)
        _seed_token(redis, token_b, target_user, family_id=family_id)

        # Token belonging to a different user must survive.
        other_token = str(uuid.uuid4())
        _seed_token(redis, other_token, "some-other-user")

        client = _build_app_with_role("admin")

        logout_resp = MagicMock()
        logout_resp.status_code = 204
        http_mock = MagicMock()
        http_mock.return_value.__aenter__.return_value.post = AsyncMock(return_value=logout_resp)

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("routes.auth_routes.httpx.AsyncClient", http_mock):
                resp = client.delete(f"/auth/admin/users/{target_user}/sessions")

        assert resp.status_code == 200

        # Target user's tokens (both family members) are gone.
        assert redis.hgetall(f"rt:{token_a}") == {}
        assert redis.hgetall(f"rt:{token_b}") == {}
        assert redis.smembers(f"rt:family:{family_id}") == set()

        # Other user's token is untouched.
        assert redis.hgetall(f"rt:{other_token}") != {}

        # Supabase admin logout endpoint was called for the target user.
        post_mock = http_mock.return_value.__aenter__.return_value.post
        post_mock.assert_called_once()
        call_args = post_mock.call_args
        assert f"/auth/v1/admin/users/{target_user}/logout" in call_args[0][0]

    def test_admin_revoke_with_no_tokens_still_returns_200(self):
        """A user with no outstanding tokens is a safe no-op, not an error."""
        redis = _fake_redis()
        client = _build_app_with_role("admin")

        logout_resp = MagicMock()
        logout_resp.status_code = 204
        http_mock = MagicMock()
        http_mock.return_value.__aenter__.return_value.post = AsyncMock(return_value=logout_resp)

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("routes.auth_routes.httpx.AsyncClient", http_mock):
                resp = client.delete("/auth/admin/users/nobody/sessions")

        assert resp.status_code == 200

    def test_admin_revoke_survives_supabase_logout_failure(self):
        """Redis revocation must not be undone just because Supabase's admin
        logout call fails — this is best-effort against the upstream API,
        same as update_password's session revocation."""
        redis = _fake_redis()
        target_user = "target-user-uuid"
        token_a = str(uuid.uuid4())
        _seed_token(redis, token_a, target_user)

        client = _build_app_with_role("admin")

        http_mock = MagicMock()
        http_mock.return_value.__aenter__.return_value.post = AsyncMock(
            side_effect=Exception("supabase unreachable")
        )

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("routes.auth_routes.httpx.AsyncClient", http_mock):
                resp = client.delete(f"/auth/admin/users/{target_user}/sessions")

        assert resp.status_code == 200
        assert redis.hgetall(f"rt:{token_a}") == {}
