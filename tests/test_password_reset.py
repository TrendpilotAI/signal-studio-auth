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
        """No auth → 401 (password complexity validated by field_validator before route runs,
        so we must send a valid password to reach the auth check)."""
        app = _make_app(authenticated=False)
        client = TestClient(app)
        resp = client.post("/auth/update-password", json={"new_password": "Newpass123"})
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
        # detail is a list of pydantic validation errors
        assert any("8 characters" in str(err) for err in resp.json()["detail"])

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
        # detail is a list of pydantic validation errors
        assert any("uppercase" in str(err).lower() for err in resp.json()["detail"])

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
        # detail is a list of pydantic validation errors
        assert any("lowercase" in str(err).lower() for err in resp.json()["detail"])

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
        # detail is a list of pydantic validation errors
        assert any("number" in str(err).lower() for err in resp.json()["detail"])


# ---------------------------------------------------------------------------
# Rate limiting tests for new routes
# ---------------------------------------------------------------------------

class TestUpdatePasswordRevokesRefreshTokens:
    """
    CRIT-5 (AUDIT Finding #5): after a successful password change, all of the
    user's outstanding opaque refresh tokens must be revoked in Redis so a
    stolen refresh token cannot outlive the password reset.
    """

    def setup_method(self):
        _update_password_calls.clear()

    def test_stolen_refresh_token_revoked_after_password_change(self):
        """A token belonging to the user must be deleted; other users' tokens must survive."""
        import fakeredis
        import uuid as uuid_mod

        redis = fakeredis.FakeRedis(decode_responses=True)
        user_sub = "user-uuid-1234"  # matches _make_jwt() default sub

        stolen_token = str(uuid_mod.uuid4())
        family_id = str(uuid_mod.uuid4())
        redis.hset(f"rt:{stolen_token}", mapping={
            "user_id": user_sub,
            "family_id": family_id,
            "parent_id": "",
            "supabase_token": "supabase-rt-stolen",
            "consumed": "0",
        })
        redis.sadd(f"rt:family:{family_id}", stolen_token)

        # A second token in the same family must also be revoked.
        sibling_token = str(uuid_mod.uuid4())
        redis.hset(f"rt:{sibling_token}", mapping={
            "user_id": user_sub,
            "family_id": family_id,
            "parent_id": stolen_token,
            "supabase_token": "supabase-rt-sibling",
            "consumed": "0",
        })
        redis.sadd(f"rt:family:{family_id}", sibling_token)

        # A token belonging to a DIFFERENT user must survive untouched.
        other_token = str(uuid_mod.uuid4())
        redis.hset(f"rt:{other_token}", mapping={
            "user_id": "some-other-user",
            "family_id": "other-family",
            "parent_id": "",
            "supabase_token": "supabase-rt-other",
            "consumed": "0",
        })
        redis.sadd("rt:family:other-family", other_token)

        app = _make_app(authenticated=True)
        token = _make_jwt(sub=user_sub)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"id": user_sub})

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_resp)
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        with patch("routes.auth_routes.get_redis", return_value=redis):
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

        # The stolen token and its family sibling must be gone.
        assert redis.hgetall(f"rt:{stolen_token}") == {}
        assert redis.hgetall(f"rt:{sibling_token}") == {}
        assert redis.smembers(f"rt:family:{family_id}") == set()

        # Another user's token must be untouched.
        assert redis.hgetall(f"rt:{other_token}").get("supabase_token") == "supabase-rt-other"
        assert other_token in redis.smembers("rt:family:other-family")

    def test_no_redis_is_a_safe_no_op(self):
        """When Redis is unavailable, password update should still succeed (best-effort)."""
        app = _make_app(authenticated=True)
        token = _make_jwt()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"id": "user-uuid-1234"})

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_resp)
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        with patch("routes.auth_routes.get_redis", return_value=None):
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


class TestUpdatePasswordRevocationUsesSupabaseClaimsSub:
    """
    P1 regression: the compat User built by supabase_auth_middleware
    (middleware/_compat.py) does NOT have a `.sub` attribute — the raw
    Supabase UUID only lives in request.state.supabase_claims['sub']. If
    update_password resolves user_sub via `getattr(user, "sub", None)`
    alone, that returns None for every real Supabase-authenticated request
    running standalone, and token revocation is silently skipped.

    This test reproduces the actual middleware shape (unlike the other
    tests in this file, which inject a MagicMock with `.sub` pre-set,
    masking the bug) and asserts revocation still fires using the sub
    resolved from supabase_claims.
    """

    def setup_method(self):
        _update_password_calls.clear()

    def test_revokes_tokens_via_supabase_claims_sub_when_user_has_no_sub_attr(self):
        import fakeredis
        import uuid as uuid_mod

        from mapping.user_mapping import supabase_claims_to_user_dict
        from middleware._compat import User as CompatUser

        user_sub = str(uuid_mod.uuid4())
        claims = {
            "sub": user_sub,
            "email": "standalone@example.com",
            "aud": "authenticated",
            "app_metadata": {"organization_id": 1, "role": "viewer"},
            "user_metadata": {"first_name": "Test", "last_name": "User"},
        }
        # This is exactly what middleware.supabase_auth_middleware._handle_supabase
        # puts on request.state.user for a real Supabase JWT.
        compat_user = CompatUser(**supabase_claims_to_user_dict(claims))
        assert not hasattr(compat_user, "sub"), (
            "sanity check: compat User must NOT expose .sub — otherwise this "
            "test stops reproducing the real middleware shape"
        )

        redis = fakeredis.FakeRedis(decode_responses=True)
        token_id = str(uuid_mod.uuid4())
        family_id = str(uuid_mod.uuid4())
        redis.hset(f"rt:{token_id}", mapping={
            "user_id": user_sub,
            "family_id": family_id,
            "parent_id": "",
            "supabase_token": "supabase-rt-standalone",
            "consumed": "0",
        })
        redis.sadd(f"rt:family:{family_id}", token_id)

        app = FastAPI()
        app.include_router(router)
        app.state.http_client = None

        @app.middleware("http")
        async def _inject_standalone_middleware_state(request: Request, call_next):
            request.state.user = compat_user
            request.state.supabase_claims = claims
            return await call_next(request)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"id": user_sub})

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_resp)
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        access_token = _make_jwt(sub=user_sub)

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
                MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

                client = TestClient(app)
                resp = client.post(
                    "/auth/update-password",
                    json={"new_password": "SuperSecret99"},
                    headers={"Authorization": f"Bearer {access_token}"},
                )

        assert resp.status_code == 200

        # The token belonging to the Supabase-claims sub must be revoked —
        # proving update_password resolved the sub from supabase_claims,
        # not from the (nonexistent) user.sub attribute.
        assert redis.hgetall(f"rt:{token_id}") == {}
        assert redis.smembers(f"rt:family:{family_id}") == set()


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
