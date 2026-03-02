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
        from routes.auth_routes import _build_rate_limiter

        with patch("routes.auth_routes.get_redis", return_value=None):
            check = _build_rate_limiter(max_calls=3, window_seconds=60)
            # 3 calls should all pass
            for _ in range(3):
                check("127.0.0.1")

    def test_in_memory_raises_at_limit(self):
        """4th call should raise HTTP 429."""
        from fastapi import HTTPException
        from routes.auth_routes import _build_rate_limiter

        with patch("routes.auth_routes.get_redis", return_value=None):
            check = _build_rate_limiter(max_calls=3, window_seconds=60)
            for _ in range(3):
                check("127.0.0.1")
            with pytest.raises(HTTPException) as exc_info:
                check("127.0.0.1")
            assert exc_info.value.status_code == 429

    def test_in_memory_different_ips_are_independent(self):
        """Different IPs should have independent counters."""
        from routes.auth_routes import _build_rate_limiter

        with patch("routes.auth_routes.get_redis", return_value=None):
            check = _build_rate_limiter(max_calls=2, window_seconds=60)
            check("1.2.3.4")
            check("1.2.3.4")
            # ip2 should still have budget
            check("5.6.7.8")
            check("5.6.7.8")


class TestRateLimiterRedis:
    """Verify Redis-backed path is taken when Redis is available."""

    def test_redis_limiter_is_used_when_available(self):
        """When Redis is reachable, the limits library should be used."""
        from routes.auth_routes import _build_rate_limiter

        mock_redis = MagicMock()
        mock_redis.ping.return_value = True

        mock_limiter = MagicMock()
        mock_limiter.hit.return_value = True  # allow

        mock_storage = MagicMock()

        with patch("routes.auth_routes.get_redis", return_value=mock_redis), \
             patch("config.redis_config.REDIS_URL", "redis://localhost:6379"), \
             patch("routes.auth_routes.get_redis", return_value=mock_redis):

            # Patch the limits imports inside the function
            with patch.dict("sys.modules", {
                "limits": MagicMock(parse=MagicMock(return_value=MagicMock())),
                "limits.storage": MagicMock(RedisStorage=MagicMock(return_value=mock_storage)),
                "limits.strategies": MagicMock(SlidingWindowRateLimiter=MagicMock(return_value=mock_limiter)),
            }):
                # Just verify it doesn't raise and the function returns callable
                check = _build_rate_limiter(max_calls=5, window_seconds=60)
                assert callable(check)

    def test_redis_limiter_raises_429_when_limit_hit(self):
        """When the Redis limiter returns False (limit hit), should raise 429."""
        from fastapi import HTTPException
        from routes.auth_routes import _build_rate_limiter

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
                check = _build_rate_limiter(max_calls=5, window_seconds=60)
                with pytest.raises(HTTPException) as exc_info:
                    check("10.0.0.1")
                assert exc_info.value.status_code == 429
                assert "Retry-After" in exc_info.value.headers


# ---------------------------------------------------------------------------
# TODO-403: Opaque refresh token helpers
# ---------------------------------------------------------------------------

class TestOpaqueTokenHelpers:
    """Unit tests for refresh token Redis helpers."""

    def test_generate_opaque_token_is_uuid(self):
        from routes.auth_routes import _generate_opaque_token
        token = _generate_opaque_token()
        # Should be a valid UUID4
        parsed = uuid.UUID(token, version=4)
        assert str(parsed) == token

    def test_store_and_consume_with_redis(self):
        """Store token in mock Redis, consume it — should return Supabase token."""
        from routes.auth_routes import _store_opaque_token, _consume_opaque_token

        store: dict[str, str] = {}
        mock_redis = MagicMock()
        mock_redis.setex = lambda key, ttl, val: store.update({key: val})
        mock_redis.getdel = lambda key: store.pop(key, None)

        with patch("routes.auth_routes.get_redis", return_value=mock_redis):
            opaque = "test-opaque-token"
            _store_opaque_token(opaque, "supabase-rt-xyz")
            result = _consume_opaque_token(opaque)

        assert result == "supabase-rt-xyz"

    def test_consume_nonexistent_token_returns_none(self):
        """Consuming a token that doesn't exist should return None."""
        from routes.auth_routes import _consume_opaque_token

        mock_redis = MagicMock()
        mock_redis.getdel = MagicMock(return_value=None)

        with patch("routes.auth_routes.get_redis", return_value=mock_redis):
            result = _consume_opaque_token("nonexistent-token")

        assert result is None

    def test_consume_is_atomic_single_use(self):
        """Consuming a token twice should return None on second attempt (rotation)."""
        from routes.auth_routes import _store_opaque_token, _consume_opaque_token

        store: dict[str, str] = {}
        mock_redis = MagicMock()
        mock_redis.setex = lambda key, ttl, val: store.update({key: val})
        mock_redis.getdel = lambda key: store.pop(key, None)

        with patch("routes.auth_routes.get_redis", return_value=mock_redis):
            opaque = "one-time-token"
            _store_opaque_token(opaque, "supabase-rt")
            first = _consume_opaque_token(opaque)
            second = _consume_opaque_token(opaque)

        assert first == "supabase-rt"
        assert second is None  # already consumed

    def test_revoke_token_deletes_from_redis(self):
        """Revoking a token should delete it from Redis."""
        from routes.auth_routes import _store_opaque_token, _revoke_opaque_token

        store: dict[str, str] = {}
        mock_redis = MagicMock()
        mock_redis.setex = lambda key, ttl, val: store.update({key: val})
        mock_redis.delete = lambda key: store.pop(key, 0) and 1 or 0

        with patch("routes.auth_routes.get_redis", return_value=mock_redis):
            opaque = "revoke-me"
            _store_opaque_token(opaque, "supabase-rt-revoke")
            _revoke_opaque_token(opaque)

        assert f"rt:{opaque}" not in store

    def test_wrap_with_opaque_token_replaces_refresh_token(self):
        """_wrap_with_opaque_token should swap out the Supabase refresh token."""
        from routes.auth_routes import _wrap_with_opaque_token

        mock_redis = MagicMock()
        mock_redis.setex = MagicMock()

        supabase_response = {
            "access_token": "access.jwt",
            "refresh_token": "supabase-native-rt",
            "token_type": "bearer",
        }

        with patch("routes.auth_routes.get_redis", return_value=mock_redis):
            result = _wrap_with_opaque_token(supabase_response)

        assert result["refresh_token"] != "supabase-native-rt"
        # Should be a valid UUID
        uuid.UUID(result["refresh_token"], version=4)
        # Access token should be unchanged
        assert result["access_token"] == "access.jwt"

    def test_wrap_with_opaque_token_no_redis_passthrough(self):
        """Without Redis, wrap still returns the response with a new UUID token stored nowhere."""
        from routes.auth_routes import _wrap_with_opaque_token

        supabase_response = {
            "access_token": "access.jwt",
            "refresh_token": "supabase-native-rt",
        }

        with patch("routes.auth_routes.get_redis", return_value=None):
            result = _wrap_with_opaque_token(supabase_response)

        # Token is replaced with an opaque UUID (store is no-op)
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
        from routes.auth_routes import REFRESH_TOKEN_PREFIX

        supabase_rt = "supabase-rt-valid"
        opaque = str(uuid.uuid4())
        store = {f"{REFRESH_TOKEN_PREFIX}{opaque}": supabase_rt}

        mock_redis = MagicMock()
        mock_redis.getdel = lambda key: store.pop(key, None)
        mock_redis.setex = lambda key, ttl, val: store.update({key: val})

        new_supabase_response = {
            "access_token": "new.access.jwt",
            "refresh_token": "new-supabase-rt",
            "token_type": "bearer",
        }

        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=mock_redis):
            with patch("httpx.AsyncClient") as mock_http:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = new_supabase_response
                mock_http.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_resp
                )
                resp = client.post("/auth/refresh", json={"refresh_token": opaque})

        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"] == "new.access.jwt"
        # Returned refresh token should be a NEW opaque UUID, not the Supabase one
        assert data["refresh_token"] != "new-supabase-rt"
        uuid.UUID(data["refresh_token"], version=4)

    def test_refresh_with_invalid_token_returns_401(self):
        """Non-existent opaque token → 401 Unauthorized."""
        mock_redis = MagicMock()
        mock_redis.getdel = MagicMock(return_value=None)

        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=mock_redis):
            resp = client.post(
                "/auth/refresh", json={"refresh_token": str(uuid.uuid4())}
            )

        assert resp.status_code == 401
        assert "expired" in resp.json()["detail"].lower() or "invalid" in resp.json()["detail"].lower()

    def test_refresh_token_single_use(self):
        """Using the same opaque token twice → 401 on second use."""
        from routes.auth_routes import REFRESH_TOKEN_PREFIX

        supabase_rt = "supabase-rt-once"
        opaque = str(uuid.uuid4())
        store = {f"{REFRESH_TOKEN_PREFIX}{opaque}": supabase_rt}

        mock_redis = MagicMock()
        mock_redis.getdel = lambda key: store.pop(key, None)
        mock_redis.setex = lambda key, ttl, val: store.update({key: val})

        new_supabase_response = {
            "access_token": "new.jwt",
            "refresh_token": "new-supa-rt",
            "token_type": "bearer",
        }

        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=mock_redis):
            with patch("httpx.AsyncClient") as mock_http:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = new_supabase_response
                mock_http.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_resp
                )
                resp1 = client.post("/auth/refresh", json={"refresh_token": opaque})
                # Second attempt with the SAME old opaque token → should fail
                resp2 = client.post("/auth/refresh", json={"refresh_token": opaque})

        assert resp1.status_code == 200
        assert resp2.status_code == 401

    def test_logout_revokes_refresh_token(self):
        """Logout with refresh_token body should remove it from Redis."""
        from routes.auth_routes import REFRESH_TOKEN_PREFIX

        opaque = str(uuid.uuid4())
        store = {f"{REFRESH_TOKEN_PREFIX}{opaque}": "supa-rt"}

        mock_redis = MagicMock()
        mock_redis.delete = lambda key: store.pop(key, None) and 1 or 0

        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=mock_redis):
            with patch("httpx.AsyncClient") as mock_http:
                mock_resp = MagicMock()
                mock_resp.status_code = 204
                mock_http.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_resp
                )
                resp = client.post(
                    "/auth/logout",
                    json={"refresh_token": opaque},
                    headers={"Authorization": "Bearer fake.access.jwt"},
                )

        assert resp.status_code == 200
        assert resp.json()["detail"] == "Logged out"
        # Token should be gone from store
        assert f"{REFRESH_TOKEN_PREFIX}{opaque}" not in store

    def test_logout_after_revoke_prevents_refresh(self):
        """After logout, the revoked token cannot be used to refresh."""
        from routes.auth_routes import REFRESH_TOKEN_PREFIX

        opaque = str(uuid.uuid4())
        store = {f"{REFRESH_TOKEN_PREFIX}{opaque}": "supa-rt"}

        mock_redis = MagicMock()
        mock_redis.delete = lambda key: store.pop(key, None) and 1 or 0
        mock_redis.getdel = lambda key: store.pop(key, None)

        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=mock_redis):
            with patch("httpx.AsyncClient") as mock_http:
                mock_resp = MagicMock()
                mock_resp.status_code = 204
                mock_http.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_resp
                )
                # Logout first
                client.post(
                    "/auth/logout",
                    json={"refresh_token": opaque},
                    headers={"Authorization": "Bearer fake.jwt"},
                )
                # Now try to refresh with the revoked token
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
        mock_redis = MagicMock()
        mock_redis.setex = MagicMock()

        client = self._build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=mock_redis):
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
        # Redis setex must have been called
        mock_redis.setex.assert_called_once()
