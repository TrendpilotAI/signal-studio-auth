"""
Tests for:
  - #837: Redis session revocation on password change (update_password)
  - #836: Admin session revocation endpoint (DELETE /auth/admin/users/{user_id}/sessions)

Run: pytest tests/test_session_revocation.py -v
"""

from __future__ import annotations

import os
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

import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from routes.auth_routes import (
    router,
    _issue_family_token,
    _revoke_all_user_tokens,
    _update_password_calls,
    REFRESH_TOKEN_PREFIX,
)
from middleware._compat import AnonymousUser
from middleware.rbac import _get_caller_role

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


def _make_app(
    *,
    authenticated: bool = False,
    user_sub: str = "user-uuid-1234",
    role: str = "viewer",
) -> FastAPI:
    """Build a minimal FastAPI app with the auth router and fake middleware state."""
    app = FastAPI()
    app.include_router(router)
    app.state.http_client = None

    @app.middleware("http")
    async def _inject_user(request: Request, call_next):
        if authenticated:
            user = MagicMock()
            user.is_authenticated = True
            user.sub = user_sub
        else:
            user = AnonymousUser()
        request.state.user = user
        request.state.supabase_claims = {
            "sub": user_sub,
            "app_metadata": {"organization_id": 1, "role": role},
            "user_metadata": {},
        } if authenticated else None
        return await call_next(request)

    return app


class FakeRedis:
    """In-memory Redis mock for testing token operations."""

    def __init__(self):
        self._data: dict[str, dict] = {}
        self._sets: dict[str, set] = {}
        self._ttls: dict[str, int] = {}

    def hset(self, key, mapping=None, **kwargs):
        if key not in self._data:
            self._data[key] = {}
        if mapping:
            self._data[key].update(mapping)
        self._data[key].update(kwargs)

    def hgetall(self, key):
        return dict(self._data.get(key, {}))

    def delete(self, *keys):
        for key in keys:
            self._data.pop(key, None)
            self._sets.pop(key, None)

    def sadd(self, key, *members):
        if key not in self._sets:
            self._sets[key] = set()
        self._sets[key].update(members)

    def srem(self, key, *members):
        if key in self._sets:
            self._sets[key] -= set(members)

    def smembers(self, key):
        return set(self._sets.get(key, set()))

    def expire(self, key, ttl):
        self._ttls[key] = ttl

    def pipeline(self):
        return FakePipeline(self)

    def scan(self, cursor=0, match="*", count=100):
        # Simple implementation: return all matching keys in one shot
        import fnmatch
        all_keys = list(self._data.keys()) + list(self._sets.keys())
        matched = [k for k in all_keys if fnmatch.fnmatch(k, match)]
        return ("0", matched)

    def ping(self):
        return True


class FakePipeline:
    def __init__(self, redis: FakeRedis):
        self._redis = redis
        self._ops: list = []

    def hset(self, key, mapping=None, **kwargs):
        self._ops.append(("hset", key, mapping, kwargs))
        return self

    def expire(self, key, ttl):
        self._ops.append(("expire", key, ttl))
        return self

    def sadd(self, key, *members):
        self._ops.append(("sadd", key, members))
        return self

    def srem(self, key, *members):
        self._ops.append(("srem", key, members))
        return self

    def delete(self, *keys):
        self._ops.append(("delete", keys))
        return self

    def execute(self):
        for op in self._ops:
            if op[0] == "hset":
                self._redis.hset(op[1], mapping=op[2], **op[3])
            elif op[0] == "expire":
                self._redis.expire(op[1], op[2])
            elif op[0] == "sadd":
                self._redis.sadd(op[1], *op[2])
            elif op[0] == "srem":
                self._redis.srem(op[1], *op[2])
            elif op[0] == "delete":
                for key in op[1]:
                    self._redis.delete(key)
        self._ops.clear()


# ---------------------------------------------------------------------------
# #837: update_password revokes Redis sessions
# ---------------------------------------------------------------------------


class TestUpdatePasswordRevokesRedisTokens:
    """Verify that update_password() revokes all opaque tokens for the user in Redis."""

    def setup_method(self):
        _update_password_calls.clear()

    def test_password_change_revokes_user_tokens_in_redis(self):
        """After successful password update, all user's opaque tokens should be deleted from Redis."""
        fake_redis = FakeRedis()
        user_id = "user-uuid-1234"

        # Pre-populate Redis with tokens for this user
        with patch("routes.auth_routes.get_redis", return_value=fake_redis):
            token1 = _issue_family_token("sb-refresh-1", user_id=user_id)
            token2 = _issue_family_token("sb-refresh-2", user_id=user_id)
            # Also add a token for a different user (should NOT be revoked)
            other_token = _issue_family_token("sb-refresh-other", user_id="other-user-999")

        # Verify tokens exist
        assert fake_redis.hgetall(f"rt:{token1}")
        assert fake_redis.hgetall(f"rt:{token2}")
        assert fake_redis.hgetall(f"rt:{other_token}")

        app = _make_app(authenticated=True, user_sub=user_id)
        token = _make_jwt(sub=user_id)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"id": user_id})

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_resp)
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        with (
            patch("routes.auth_routes.get_redis", return_value=fake_redis),
            patch("routes.auth_routes.httpx.AsyncClient") as MockClient,
        ):
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            resp = client.post(
                "/auth/update-password",
                json={"new_password": "NewSecure1"},
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200

        # User's tokens should be revoked
        assert not fake_redis.hgetall(f"rt:{token1}")
        assert not fake_redis.hgetall(f"rt:{token2}")

        # Other user's token should still exist
        assert fake_redis.hgetall(f"rt:{other_token}")

    def test_password_change_without_redis_still_succeeds(self):
        """Password update should succeed even when Redis is unavailable."""
        app = _make_app(authenticated=True, user_sub="user-uuid-1234")
        token = _make_jwt()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"id": "user-uuid-1234"})

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_resp)
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        with (
            patch("routes.auth_routes.get_redis", return_value=None),
            patch("routes.auth_routes.httpx.AsyncClient") as MockClient,
        ):
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            resp = client.post(
                "/auth/update-password",
                json={"new_password": "NewSecure1"},
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        assert "updated" in resp.json()["message"].lower()


# ---------------------------------------------------------------------------
# #836: Admin session revocation endpoint
# ---------------------------------------------------------------------------


class TestAdminRevokeUserSessions:
    """Tests for DELETE /auth/admin/users/{user_id}/sessions."""

    def test_unauthenticated_returns_401(self):
        """Unauthenticated caller → 401."""
        app = _make_app(authenticated=False)
        client = TestClient(app)
        resp = client.delete("/auth/admin/users/some-user-id/sessions")
        assert resp.status_code == 401

    def test_non_admin_returns_403(self):
        """Authenticated viewer → 403."""
        app = _make_app(authenticated=True, role="viewer")
        token = _make_jwt()
        client = TestClient(app)
        resp = client.delete(
            "/auth/admin/users/some-user-id/sessions",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
        assert "admin" in resp.json()["detail"].lower()

    def test_admin_revokes_sessions_successfully(self):
        """Admin caller → 200, user's tokens revoked."""
        fake_redis = FakeRedis()
        target_user = "target-user-uuid"

        # Pre-populate Redis with tokens for target user
        with patch("routes.auth_routes.get_redis", return_value=fake_redis):
            token1 = _issue_family_token("sb-1", user_id=target_user)
            token2 = _issue_family_token("sb-2", user_id=target_user)
            # Another user's token (should survive)
            safe_token = _issue_family_token("sb-safe", user_id="innocent-user")

        app = _make_app(authenticated=True, user_sub="admin-user-uuid", role="admin")
        token = _make_jwt(sub="admin-user-uuid")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        with (
            patch("routes.auth_routes.get_redis", return_value=fake_redis),
            patch("routes.auth_routes.httpx.AsyncClient") as MockClient,
        ):
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            resp = client.delete(
                f"/auth/admin/users/{target_user}/sessions",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["revoked_tokens"] == 2
        assert target_user in data["detail"]

        # Target user's tokens should be gone
        assert not fake_redis.hgetall(f"rt:{token1}")
        assert not fake_redis.hgetall(f"rt:{token2}")

        # Innocent user's token should survive
        assert fake_redis.hgetall(f"rt:{safe_token}")

    def test_admin_revoke_no_sessions_returns_zero(self):
        """Admin revoking sessions for user with no tokens → 200 with revoked_tokens=0."""
        fake_redis = FakeRedis()

        app = _make_app(authenticated=True, user_sub="admin-user-uuid", role="admin")
        token = _make_jwt(sub="admin-user-uuid")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        with (
            patch("routes.auth_routes.get_redis", return_value=fake_redis),
            patch("routes.auth_routes.httpx.AsyncClient") as MockClient,
        ):
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            resp = client.delete(
                "/auth/admin/users/nonexistent-user/sessions",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        assert resp.json()["revoked_tokens"] == 0

    def test_admin_revoke_calls_supabase_admin_logout(self):
        """Verify the Supabase admin logout API is called for the target user."""
        fake_redis = FakeRedis()
        target_user = "target-user-uuid"

        app = _make_app(authenticated=True, user_sub="admin-user-uuid", role="admin")
        token = _make_jwt(sub="admin-user-uuid")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        with (
            patch("routes.auth_routes.get_redis", return_value=fake_redis),
            patch("routes.auth_routes.httpx.AsyncClient") as MockClient,
        ):
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            client.delete(
                f"/auth/admin/users/{target_user}/sessions",
                headers={"Authorization": f"Bearer {token}"},
            )

        # Verify Supabase admin logout was called
        mock_client.post.assert_called_once()
        call_url = mock_client.post.call_args[0][0]
        assert f"/auth/v1/admin/users/{target_user}/logout" in call_url

    def test_admin_revoke_without_redis_still_calls_supabase(self):
        """When Redis is down, Supabase admin logout should still be called."""
        target_user = "target-user-uuid"

        app = _make_app(authenticated=True, user_sub="admin-user-uuid", role="admin")
        token = _make_jwt(sub="admin-user-uuid")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        with (
            patch("routes.auth_routes.get_redis", return_value=None),
            patch("routes.auth_routes.httpx.AsyncClient") as MockClient,
        ):
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(app)
            resp = client.delete(
                f"/auth/admin/users/{target_user}/sessions",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        assert resp.json()["revoked_tokens"] == 0
        # Supabase should still be called
        mock_client.post.assert_called_once()


# ---------------------------------------------------------------------------
# _revoke_all_user_tokens unit tests
# ---------------------------------------------------------------------------


class TestRevokeAllUserTokens:
    """Direct unit tests for the _revoke_all_user_tokens helper."""

    def test_returns_zero_when_redis_unavailable(self):
        with patch("routes.auth_routes.get_redis", return_value=None):
            assert _revoke_all_user_tokens("user-123") == 0

    def test_returns_zero_for_empty_user_id(self):
        with patch("routes.auth_routes.get_redis", return_value=FakeRedis()):
            assert _revoke_all_user_tokens("") == 0

    def test_revokes_correct_user_tokens_only(self):
        fake_redis = FakeRedis()
        with patch("routes.auth_routes.get_redis", return_value=fake_redis):
            t1 = _issue_family_token("sb-1", user_id="user-A")
            t2 = _issue_family_token("sb-2", user_id="user-A")
            t3 = _issue_family_token("sb-3", user_id="user-B")

        with patch("routes.auth_routes.get_redis", return_value=fake_redis):
            count = _revoke_all_user_tokens("user-A")

        assert count == 2
        assert not fake_redis.hgetall(f"rt:{t1}")
        assert not fake_redis.hgetall(f"rt:{t2}")
        assert fake_redis.hgetall(f"rt:{t3}")  # user-B's token intact

    def test_revokes_multiple_families(self):
        """Tokens across multiple families for same user should all be revoked."""
        fake_redis = FakeRedis()
        with patch("routes.auth_routes.get_redis", return_value=fake_redis):
            t1 = _issue_family_token("sb-1", user_id="user-X", family_id="fam-1")
            t2 = _issue_family_token("sb-2", user_id="user-X", family_id="fam-2")

        with patch("routes.auth_routes.get_redis", return_value=fake_redis):
            count = _revoke_all_user_tokens("user-X")

        assert count == 2
        assert not fake_redis.hgetall(f"rt:{t1}")
        assert not fake_redis.hgetall(f"rt:{t2}")
