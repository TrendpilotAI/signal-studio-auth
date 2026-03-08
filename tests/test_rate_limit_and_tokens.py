"""
Tests for TODO-402 (Redis-backed rate limiter) and TODO-403 (refresh token rotation).

Run: pytest tests/test_rate_limit_and_tokens.py -v
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Set env before importing our modules
os.environ.setdefault("SUPABASE_JWT_SECRET", "test-secret-at-least-32-chars-long!!")
os.environ.setdefault("SUPABASE_URL", "http://localhost:54321")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test-service-key")
os.environ.setdefault("AUTH_MODE", "supabase")

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_supabase_token_response(email: str = "test@example.com") -> dict:
    """Simulate a Supabase /token response."""
    return {
        "access_token": "eyJ.fake.jwt",
        "token_type": "bearer",
        "expires_in": 3600,
        "refresh_token": "supabase-original-refresh-token-abc123",
        "user": {"email": email},
    }


# ---------------------------------------------------------------------------
# TODO-402: Rate limiter tests
# ---------------------------------------------------------------------------

class TestRateLimiterFallback:
    """Verify in-memory fallback when Redis is unavailable."""

    def test_in_memory_allows_under_limit(self):
        """Check() should not raise when under the limit."""
        from collections import defaultdict
        from threading import Lock
        from routes.auth_routes import _make_shim_check

        calls: dict = defaultdict(list)
        lock = Lock()
        check = _make_shim_check(calls, lock, max_calls=3, window_seconds=60)
        # 3 calls should all pass
        for _ in range(3):
            check("127.0.0.1")

    def test_in_memory_raises_at_limit(self):
        """4th call should raise HTTP 429."""
        from collections import defaultdict
        from threading import Lock
        from fastapi import HTTPException
        from routes.auth_routes import _make_shim_check

        calls: dict = defaultdict(list)
        lock = Lock()
        check = _make_shim_check(calls, lock, max_calls=3, window_seconds=60)
        for _ in range(3):
            check("127.0.0.1")
        with pytest.raises(HTTPException) as exc_info:
            check("127.0.0.1")
        assert exc_info.value.status_code == 429

    def test_in_memory_different_ips_are_independent(self):
        """Different IPs should have independent counters."""
        from collections import defaultdict
        from threading import Lock
        from routes.auth_routes import _make_shim_check

        calls: dict = defaultdict(list)
        lock = Lock()
        check = _make_shim_check(calls, lock, max_calls=2, window_seconds=60)
        check("1.2.3.4")
        check("1.2.3.4")
        # ip2 should still have budget
        check("5.6.7.8")
        check("5.6.7.8")


class TestRateLimiterRedis:
    """Verify Redis-backed path is taken when Redis is available."""

    def test_redis_limiter_is_used_when_available(self):
        """When Redis is reachable, the limits library should be used."""
        from collections import defaultdict
        from threading import Lock
        from routes.auth_routes import _redis_or_memory_check

        calls: dict = defaultdict(list)
        lock = Lock()
        mock_redis = MagicMock()
        mock_limiter = MagicMock()
        mock_limiter.hit.return_value = True  # allow
        mock_storage = MagicMock()

        with patch("routes.auth_routes.get_redis", return_value=mock_redis), \
             patch("config.redis_config.REDIS_URL", "redis://localhost:6379"):
            with patch.dict("sys.modules", {
                "limits": MagicMock(parse=MagicMock(return_value=MagicMock())),
                "limits.storage": MagicMock(RedisStorage=MagicMock(return_value=mock_storage)),
                "limits.strategies": MagicMock(SlidingWindowRateLimiter=MagicMock(return_value=mock_limiter)),
            }):
                check = _redis_or_memory_check(calls, lock, max_calls=5, window_seconds=60)
                assert callable(check)

    def test_redis_limiter_raises_429_when_limit_hit(self):
        """When the Redis limiter returns False (limit hit), should raise 429."""
        from collections import defaultdict
        from threading import Lock
        from fastapi import HTTPException
        from routes.auth_routes import _redis_or_memory_check

        calls: dict = defaultdict(list)
        lock = Lock()
        mock_redis = MagicMock()
        mock_limiter = MagicMock()
        mock_limiter.hit.return_value = False  # limit exceeded
        mock_storage = MagicMock()

        with patch("routes.auth_routes.get_redis", return_value=mock_redis):
            with patch.dict("sys.modules", {
                "limits": MagicMock(parse=MagicMock(return_value=MagicMock())),
                "limits.storage": MagicMock(RedisStorage=MagicMock(return_value=mock_storage)),
                "limits.strategies": MagicMock(SlidingWindowRateLimiter=MagicMock(return_value=mock_limiter)),
            }):
                check = _redis_or_memory_check(calls, lock, max_calls=5, window_seconds=60)
                with pytest.raises(HTTPException) as exc_info:
                    check("10.0.0.1")
                assert exc_info.value.status_code == 429
                assert "Retry-After" in exc_info.value.headers


# ---------------------------------------------------------------------------
# TODO-403: Opaque refresh token helpers
# ---------------------------------------------------------------------------

def _fake_redis_rl():
    """Return a fresh fakeredis instance (decode_responses=True) for rate-limit/token tests."""
    import fakeredis
    return fakeredis.FakeRedis(decode_responses=True)


def _seed_rt(redis, token_id: str, supabase_token: str,
             family_id: str = None, parent_id: str = "", consumed: str = "0") -> str:
    """Seed a family-tracking token hash + family SET into fakeredis."""
    fid = family_id or str(uuid.uuid4())
    redis.hset(f"rt:{token_id}", mapping={
        "user_id": "user-test",
        "family_id": fid,
        "parent_id": parent_id,
        "supabase_token": supabase_token,
        "consumed": consumed,
    })
    redis.expire(f"rt:{token_id}", 600)
    redis.sadd(f"rt:family:{fid}", token_id)
    redis.expire(f"rt:family:{fid}", 600)
    return fid


class TestOpaqueTokenHelpers:
    """Unit tests for refresh token Redis helpers (family tracking, TODO-603)."""

    def test_issue_family_token_is_uuid(self):
        """_issue_family_token returns a valid UUID4."""
        from routes.auth_routes import _issue_family_token
        redis = _fake_redis_rl()
        with patch("routes.auth_routes.get_redis", return_value=redis):
            token_id = _issue_family_token("supabase-rt-xyz")
        parsed = uuid.UUID(token_id, version=4)
        assert str(parsed) == token_id

    def test_issue_family_token_stores_hash_and_family_set(self):
        """Issued token must be stored as a hash and in the family SET."""
        from routes.auth_routes import _issue_family_token
        redis = _fake_redis_rl()
        with patch("routes.auth_routes.get_redis", return_value=redis):
            token_id = _issue_family_token("supabase-rt-xyz", user_id="user-1")
        data = redis.hgetall(f"rt:{token_id}")
        assert data["supabase_token"] == "supabase-rt-xyz"
        assert data["consumed"] == "0"
        assert data["user_id"] == "user-1"
        fid = data["family_id"]
        assert token_id in redis.smembers(f"rt:family:{fid}")

    def test_issue_family_token_child_shares_family(self):
        """Child token must share the parent's family_id."""
        from routes.auth_routes import _issue_family_token
        redis = _fake_redis_rl()
        family_id = str(uuid.uuid4())
        parent_id = str(uuid.uuid4())
        with patch("routes.auth_routes.get_redis", return_value=redis):
            child_id = _issue_family_token("sb-child", parent_id=parent_id, family_id=family_id)
        child_data = redis.hgetall(f"rt:{child_id}")
        assert child_data["family_id"] == family_id
        assert child_data["parent_id"] == parent_id

    def test_revoke_token_deletes_hash_and_removes_from_set(self):
        """Revoking a token should delete the hash and remove it from the family SET."""
        from routes.auth_routes import _revoke_opaque_token
        redis = _fake_redis_rl()
        token_id = str(uuid.uuid4())
        family_id = _seed_rt(redis, token_id, "supabase-rt-revoke")

        with patch("routes.auth_routes.get_redis", return_value=redis):
            _revoke_opaque_token(token_id)

        assert redis.hgetall(f"rt:{token_id}") == {}
        assert token_id not in redis.smembers(f"rt:family:{family_id}")

    def test_wrap_with_opaque_token_replaces_refresh_token(self):
        """_wrap_with_opaque_token should swap out the Supabase refresh token."""
        from routes.auth_routes import _wrap_with_opaque_token
        redis = _fake_redis_rl()
        supabase_response = {
            "access_token": "access.jwt",
            "refresh_token": "supabase-native-rt",
            "token_type": "bearer",
        }
        with patch("routes.auth_routes.get_redis", return_value=redis):
            result = _wrap_with_opaque_token(supabase_response)
        assert result["refresh_token"] != "supabase-native-rt"
        uuid.UUID(result["refresh_token"], version=4)
        assert result["access_token"] == "access.jwt"

    def test_wrap_with_opaque_token_no_redis_passthrough(self):
        """Without Redis, wrap still returns the response with a new UUID token."""
        from routes.auth_routes import _wrap_with_opaque_token
        supabase_response = {
            "access_token": "access.jwt",
            "refresh_token": "supabase-native-rt",
        }
        with patch("routes.auth_routes.get_redis", return_value=None):
            result = _wrap_with_opaque_token(supabase_response)
        assert result["refresh_token"] != "supabase-native-rt"
        uuid.UUID(result["refresh_token"], version=4)


# ---------------------------------------------------------------------------
# TODO-403: Route integration tests (mock Supabase + Redis)
# ---------------------------------------------------------------------------

class TestRefreshTokenRotation:
    """Integration tests for /auth/refresh and /auth/logout."""

    def _build_test_app(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from routes.auth_routes import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app, raise_server_exceptions=True)

    def test_refresh_with_valid_opaque_token(self):
        """Valid opaque token → new access + refresh tokens returned."""
        redis = _fake_redis_rl()
        opaque = str(uuid.uuid4())
        _seed_rt(redis, opaque, "supabase-rt-valid")

        new_supabase_response = {
            "access_token": "new.access.jwt",
            "refresh_token": "new-supabase-rt",
            "token_type": "bearer",
        }

        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("httpx.AsyncClient") as mock_http:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = new_supabase_response
                mock_http.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
                resp = client.post("/auth/refresh", json={"refresh_token": opaque})

        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"] == "new.access.jwt"
        assert data["refresh_token"] != "new-supabase-rt"
        uuid.UUID(data["refresh_token"], version=4)

    def test_refresh_with_invalid_token_returns_401(self):
        """Non-existent opaque token → 401 Unauthorized."""
        redis = _fake_redis_rl()  # empty

        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            resp = client.post("/auth/refresh", json={"refresh_token": str(uuid.uuid4())})

        assert resp.status_code == 401
        assert "expired" in resp.json()["detail"].lower() or "invalid" in resp.json()["detail"].lower()

    def test_refresh_token_single_use(self):
        """Using the same opaque token twice → 401 on second use (consumed)."""
        redis = _fake_redis_rl()
        opaque = str(uuid.uuid4())
        _seed_rt(redis, opaque, "supabase-rt-once")

        new_supabase_response = {
            "access_token": "new.jwt",
            "refresh_token": "new-supa-rt",
            "token_type": "bearer",
        }

        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("httpx.AsyncClient") as mock_http:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = new_supabase_response
                mock_http.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
                resp1 = client.post("/auth/refresh", json={"refresh_token": opaque})
                resp2 = client.post("/auth/refresh", json={"refresh_token": opaque})

        assert resp1.status_code == 200
        assert resp2.status_code == 401

    def test_logout_revokes_refresh_token(self):
        """Logout with refresh_token body should remove it from Redis."""
        redis = _fake_redis_rl()
        opaque = str(uuid.uuid4())
        _seed_rt(redis, opaque, "supa-rt")

        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("httpx.AsyncClient") as mock_http:
                mock_resp = MagicMock()
                mock_resp.status_code = 204
                mock_http.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
                resp = client.post(
                    "/auth/logout",
                    json={"refresh_token": opaque},
                    headers={"Authorization": "Bearer fake.access.jwt"},
                )

        assert resp.status_code == 200
        assert resp.json()["detail"] == "Logged out"
        assert redis.hgetall(f"rt:{opaque}") == {}

    def test_logout_after_revoke_prevents_refresh(self):
        """After logout, the revoked token cannot be used to refresh."""
        redis = _fake_redis_rl()
        opaque = str(uuid.uuid4())
        _seed_rt(redis, opaque, "supa-rt")

        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("httpx.AsyncClient") as mock_http:
                mock_resp = MagicMock()
                mock_resp.status_code = 204
                mock_http.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
                client.post(
                    "/auth/logout",
                    json={"refresh_token": opaque},
                    headers={"Authorization": "Bearer fake.jwt"},
                )
                resp = client.post("/auth/refresh", json={"refresh_token": opaque})

        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TODO-403: Login / signup wrap integration
# ---------------------------------------------------------------------------

class TestLoginSignupWrapOpaque:
    """Verify login/signup return opaque refresh tokens."""

    def _build_test_app(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from routes.auth_routes import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_login_returns_opaque_refresh_token(self):
        supabase_response = _make_supabase_token_response()
        redis = _fake_redis_rl()

        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("routes.auth_routes._login_limiter") as mock_limiter:
                mock_limiter.check = MagicMock()  # skip rate limit
                with patch("httpx.AsyncClient") as mock_http:
                    mock_resp = MagicMock()
                    mock_resp.status_code = 200
                    mock_resp.json.return_value = supabase_response
                    mock_http.return_value.__aenter__.return_value.post = AsyncMock(
                        return_value=mock_resp
                    )
                    resp = client.post(
                        "/auth/login",
                        json={"email": "test@example.com", "password": "pass"},
                    )

        assert resp.status_code == 200
        data = resp.json()
        # Must not be the raw Supabase refresh token
        assert data["refresh_token"] != supabase_response["refresh_token"]
        # Must be a valid UUID4
        uuid.UUID(data["refresh_token"], version=4)
        # Token must be stored as a hash in Redis
        token_data = redis.hgetall(f"rt:{data['refresh_token']}")
        assert token_data.get("supabase_token") == supabase_response["refresh_token"]
        assert token_data.get("consumed") == "0"
