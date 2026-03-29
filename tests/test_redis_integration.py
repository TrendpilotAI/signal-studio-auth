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
    """Return a fresh in-process FakeRedis instance (decode_responses matches production config)."""
    return fakeredis.FakeRedis(decode_responses=True)


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

def _seed_family_token(redis, token_id: str, supabase_token: str,
                        user_id: str = "user-123",
                        family_id: Optional[str] = None,
                        parent_id: str = "",
                        consumed: str = "0",
                        ttl: int = 600) -> str:
    """Helper: seed a token hash + family SET into fakeredis."""
    fid = family_id or str(uuid.uuid4())
    redis.hset(f"rt:{token_id}", mapping={
        "user_id": user_id,
        "family_id": fid,
        "parent_id": parent_id,
        "supabase_token": supabase_token,
        "consumed": consumed,
    })
    redis.expire(f"rt:{token_id}", ttl)
    redis.sadd(f"rt:family:{fid}", token_id)
    redis.expire(f"rt:family:{fid}", ttl)
    return fid


from typing import Optional


class TestRefreshTokenRotation:
    """
    /auth/refresh Redis round-trip tests.

    fakeredis is patched in as the get_redis() return value so all
    hash / set operations use real Redis semantics.
    """

    def test_valid_token_issues_new_token_and_consumes_old(self):
        """POST /auth/refresh with valid opaque token → new access+refresh tokens returned."""
        redis = _fake_redis()
        token_id = str(uuid.uuid4())
        family_id = _seed_family_token(redis, token_id, "supabase-rt-original")

        new_response = _make_supabase_token_response()
        client = _build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("httpx.AsyncClient", _mock_supabase_post(new_response)):
                resp = client.post("/auth/refresh", json={"refresh_token": token_id})

        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"] == "new.access.jwt"

        # Returned refresh token must be a NEW opaque UUID
        new_token_id = data["refresh_token"]
        assert new_token_id != token_id
        uuid.UUID(new_token_id, version=4)

        # Old token must be marked consumed (not deleted — needed for theft detection)
        old_data = redis.hgetall(f"rt:{token_id}")
        assert old_data.get("consumed") == "1"

        # New token must be stored in Redis in the same family
        new_data = redis.hgetall(f"rt:{new_token_id}")
        assert new_data.get("family_id") == family_id
        assert new_data.get("parent_id") == token_id
        assert new_data.get("consumed") == "0"

        # Both tokens must be members of the family SET
        family_members = redis.smembers(f"rt:family:{family_id}")
        assert token_id in family_members
        assert new_token_id in family_members

    def test_consumed_token_returns_401_and_revokes_family(self):
        """
        POST /auth/refresh with already-rotated (consumed) token → 401 AND entire
        family is revoked (theft detection).
        """
        redis = _fake_redis()
        family_id = str(uuid.uuid4())

        # Simulate: token_a was consumed (rotated to token_b)
        token_a = str(uuid.uuid4())
        token_b = str(uuid.uuid4())
        _seed_family_token(redis, token_a, "sb-rt-a", family_id=family_id, consumed="1")
        _seed_family_token(redis, token_b, "sb-rt-b", family_id=family_id, parent_id=token_a)

        client = _build_test_app()
        with patch("routes.auth_routes.get_redis", return_value=redis):
            # Attacker reuses the consumed token_a
            resp = client.post("/auth/refresh", json={"refresh_token": token_a})

        assert resp.status_code == 401
        detail = resp.json()["detail"].lower()
        assert "reuse" in detail or "revoked" in detail or "theft" in detail

        # Both tokens must be deleted from Redis
        assert redis.hgetall(f"rt:{token_a}") == {}
        assert redis.hgetall(f"rt:{token_b}") == {}
        # Family SET must be deleted
        assert redis.smembers(f"rt:family:{family_id}") == set()

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

    def test_legitimate_rotation_then_theft_revokes_all(self):
        """
        Full scenario: login → legitimate rotate → attacker reuses original token
        → both the original and the child should be revoked.
        """
        redis = _fake_redis()
        family_id = str(uuid.uuid4())

        # Initial token issued at login
        original_token = str(uuid.uuid4())
        _seed_family_token(redis, original_token, "sb-original", family_id=family_id)

        new_response = _make_supabase_token_response(refresh="sb-new")
        client = _build_test_app()

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("httpx.AsyncClient", _mock_supabase_post(new_response)):
                # Legitimate user rotates
                resp1 = client.post("/auth/refresh", json={"refresh_token": original_token})
        assert resp1.status_code == 200
        child_token = resp1.json()["refresh_token"]

        # Attacker (or network replay) reuses the now-consumed original token
        with patch("routes.auth_routes.get_redis", return_value=redis):
            resp2 = client.post("/auth/refresh", json={"refresh_token": original_token})
        assert resp2.status_code == 401

        # Both original and child must now be revoked
        assert redis.hgetall(f"rt:{original_token}") == {}
        assert redis.hgetall(f"rt:{child_token}") == {}
        assert redis.smembers(f"rt:family:{family_id}") == set()

    def test_legitimate_user_refresh_after_theft_detection_fails(self):
        """
        After theft revokes the family, the legitimate user's child token
        must also be invalid (forces full re-login).
        """
        redis = _fake_redis()
        family_id = str(uuid.uuid4())

        original = str(uuid.uuid4())
        child = str(uuid.uuid4())
        # Attacker already rotated original → child, original is consumed
        _seed_family_token(redis, original, "sb-orig", family_id=family_id, consumed="1")
        _seed_family_token(redis, child, "sb-child", family_id=family_id, parent_id=original)

        client = _build_test_app()
        with patch("routes.auth_routes.get_redis", return_value=redis):
            # Legitimate user (with original) detects theft → revokes family
            client.post("/auth/refresh", json={"refresh_token": original})
            # Attacker tries to use child token — should also fail (revoked)
            resp = client.post("/auth/refresh", json={"refresh_token": child})

        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TestLogoutRevocation
# ---------------------------------------------------------------------------

class TestLogoutRevocation:
    """
    /auth/logout revocation: token removed from Redis, subsequent refresh fails.
    """

    def test_logout_revokes_token_in_redis(self):
        """POST /auth/logout removes the opaque token from Redis."""
        redis = _fake_redis()
        opaque = str(uuid.uuid4())
        _seed_family_token(redis, opaque, "supabase-rt-logout")

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
        # Token hash must be gone from Redis
        assert redis.hgetall(f"rt:{opaque}") == {}

    def test_revoked_token_cannot_refresh(self):
        """After logout, the same token must be rejected by /auth/refresh (401)."""
        redis = _fake_redis()
        opaque = str(uuid.uuid4())
        _seed_family_token(redis, opaque, "supabase-rt-to-revoke")

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


# ---------------------------------------------------------------------------
# TestRevokeAllUserTokens
# ---------------------------------------------------------------------------

class TestRevokeAllUserTokens:
    """
    Security fix: password change must revoke ALL opaque refresh tokens.

    Verifies that _revoke_all_user_tokens() deletes every rt:{token_id} hash
    for the given user, removes their entries from family SETs, and clears the
    user:tokens:{user_id} index.
    """

    def test_revoke_all_tokens_clears_user_index(self):
        """After revocation, all token hashes and the user index should be gone."""
        from routes.auth_routes import _issue_family_token, _revoke_all_user_tokens, USER_TOKENS_PREFIX

        redis = _fake_redis()
        user_id = "user-abc-123"

        # Issue three tokens for the same user
        with patch("routes.auth_routes.get_redis", return_value=redis):
            t1 = _issue_family_token("sb_tok_1", user_id=user_id)
            t2 = _issue_family_token("sb_tok_2", user_id=user_id)
            t3 = _issue_family_token("sb_tok_3", user_id=user_id)

        # Confirm they exist in Redis
        assert redis.hget(f"rt:{t1}", "user_id") == user_id
        assert redis.hget(f"rt:{t2}", "user_id") == user_id
        assert redis.hget(f"rt:{t3}", "user_id") == user_id
        assert redis.sismember(f"{USER_TOKENS_PREFIX}{user_id}", t1)

        # Revoke all
        with patch("routes.auth_routes.get_redis", return_value=redis):
            count = _revoke_all_user_tokens(user_id)

        assert count == 3
        # All token hashes gone
        assert not redis.exists(f"rt:{t1}")
        assert not redis.exists(f"rt:{t2}")
        assert not redis.exists(f"rt:{t3}")
        # User index gone
        assert not redis.exists(f"{USER_TOKENS_PREFIX}{user_id}")

    def test_tokens_of_other_users_untouched(self):
        """Revoking one user's tokens must not affect another user's tokens."""
        from routes.auth_routes import _issue_family_token, _revoke_all_user_tokens

        redis = _fake_redis()
        user_a = "user-aaa"
        user_b = "user-bbb"

        with patch("routes.auth_routes.get_redis", return_value=redis):
            ta = _issue_family_token("sb_tok_a", user_id=user_a)
            tb = _issue_family_token("sb_tok_b", user_id=user_b)
            _revoke_all_user_tokens(user_a)

        # user_a's token gone
        assert not redis.exists(f"rt:{ta}")
        # user_b's token still intact
        assert redis.hget(f"rt:{tb}", "user_id") == user_b

    def test_revoke_returns_zero_when_no_redis(self):
        """No Redis → graceful no-op, returns 0."""
        from routes.auth_routes import _revoke_all_user_tokens

        with patch("routes.auth_routes.get_redis", return_value=None):
            count = _revoke_all_user_tokens("any-user")

        assert count == 0
