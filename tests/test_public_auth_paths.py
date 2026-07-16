"""
Tests for the P2 middleware-ordering fix: supabase_auth_middleware runs on
EVERY route (main.py wires it globally), so a client that always attaches
a Bearer access token would get 401'd by the middleware itself on public
auth endpoints (/auth/login, /auth/signup, /auth/refresh,
/auth/reset-password, /health) whenever that token is expired or invalid —
before the route handler ever runs. That breaks /auth/refresh in
particular: the whole point of refresh is to recover from an expired
access token using the body's refresh token, but the middleware would 401
first.

Public auth endpoints must treat the Authorization header as optional:
an expired/invalid bearer must NOT block the request from reaching the
handler. Protected endpoints (/auth/me, /auth/update-password) must keep
requiring valid auth.

Run: pytest tests/test_public_auth_paths.py -v
"""

from __future__ import annotations

import importlib
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("SUPABASE_JWT_SECRET", "test-secret-at-least-32-chars-long!!")
os.environ.setdefault("SUPABASE_URL", "http://localhost:54321")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test-service-key")
os.environ.setdefault("AUTH_MODE", "dual")

import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

SUPABASE_SECRET = os.environ["SUPABASE_JWT_SECRET"]
SUPABASE_URL = os.environ["SUPABASE_URL"]


@pytest.fixture(autouse=True)
def _reset_rate_limiter_state():
    """Rate limiter counters are process-global dicts keyed by client IP
    (TestClient always uses the same fixed IP), so they must be cleared
    before every test in this module — otherwise earlier test files that
    exercise the same endpoints (e.g. TestPasswordResetRateLimit in
    test_password_reset.py) leave counters tripped and this file's
    "proceeds despite bad bearer" assertions flake to 429 depending on
    test execution order."""
    import routes.auth_routes as auth_routes
    auth_routes._login_calls.clear()
    auth_routes._signup_calls.clear()
    auth_routes._reset_password_calls.clear()
    auth_routes._update_password_calls.clear()
    yield


def _make_supabase_jwt(
    sub: str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    email: str = "expired@example.com",
    expired: bool = True,
) -> str:
    """A genuine Supabase-shaped HS256 JWT, expired by default — this is
    the "client always attaches its (possibly stale) access token" case."""
    now = datetime.now(timezone.utc)
    exp = now - timedelta(hours=1) if expired else now + timedelta(hours=1)
    payload = {
        "sub": sub,
        "email": email,
        "aud": "authenticated",
        "iat": int((now - timedelta(hours=2)).timestamp()),
        "exp": int(exp.timestamp()),
        "app_metadata": {"organization_id": 1, "role": "viewer"},
        "user_metadata": {"first_name": "Test", "last_name": "User"},
    }
    return pyjwt.encode(payload, SUPABASE_SECRET, algorithm="HS256")


def _reload_middleware_for_mode(auth_mode: str):
    """Force config.supabase_config.AUTH_MODE and the middleware module's
    AUTH_MODE binding to the given mode (mirrors tests/test_auth_modes.py)."""
    with patch.dict(os.environ, {"AUTH_MODE": auth_mode}):
        import config.supabase_config as cfg
        importlib.reload(cfg)

        import middleware.supabase_auth_middleware as mw
        importlib.reload(mw)

    return mw.supabase_auth_middleware


def _reload_main_app(auth_mode: str = "dual"):
    """Reload main.py fresh, wired with the given AUTH_MODE — exercises the
    real global middleware registration in main.py, not a test-built app."""
    _reload_middleware_for_mode(auth_mode)
    with patch.dict(os.environ, {"AUTH_MODE": auth_mode}):
        if "main" in sys.modules:
            main = importlib.reload(sys.modules["main"])
        else:
            import main
    return main


def _fake_redis():
    import fakeredis
    return fakeredis.FakeRedis(decode_responses=True)


def _seed_rt(redis, token_id: str, supabase_token: str, user_id: str = "user-test") -> str:
    family_id = str(uuid.uuid4())
    redis.hset(f"rt:{token_id}", mapping={
        "user_id": user_id,
        "family_id": family_id,
        "parent_id": "",
        "supabase_token": supabase_token,
        "consumed": "0",
    })
    redis.sadd(f"rt:family:{family_id}", token_id)
    return family_id


# ---------------------------------------------------------------------------
# POST /auth/refresh must succeed on an expired bearer + valid body token
# ---------------------------------------------------------------------------

class TestRefreshSucceedsDespiteExpiredBearer:
    def test_refresh_with_expired_bearer_and_valid_body_token_succeeds(self):
        main = _reload_main_app("dual")

        redis = _fake_redis()
        opaque = str(uuid.uuid4())
        _seed_rt(redis, opaque, "supabase-rt-valid")

        new_supabase_response = {
            "access_token": "new.access.jwt",
            "refresh_token": "new-supabase-rt",
            "token_type": "bearer",
        }

        expired_bearer = _make_supabase_jwt(expired=True)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = new_supabase_response

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
                MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

                client = TestClient(main.app)
                resp = client.post(
                    "/auth/refresh",
                    json={"refresh_token": opaque},
                    headers={"Authorization": f"Bearer {expired_bearer}"},
                )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["access_token"] == "new.access.jwt"
        assert data["refresh_token"] != "new-supabase-rt"

    def test_refresh_with_garbage_bearer_and_valid_body_token_succeeds(self):
        """Not just expired — a plain garbage bearer token must not block
        /auth/refresh from reaching the handler either."""
        main = _reload_main_app("dual")

        redis = _fake_redis()
        opaque = str(uuid.uuid4())
        _seed_rt(redis, opaque, "supabase-rt-valid")

        new_supabase_response = {
            "access_token": "new.access.jwt",
            "refresh_token": "new-supabase-rt",
            "token_type": "bearer",
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = new_supabase_response

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("routes.auth_routes.get_redis", return_value=redis):
            with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
                MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

                client = TestClient(main.app)
                resp = client.post(
                    "/auth/refresh",
                    json={"refresh_token": opaque},
                    headers={"Authorization": "Bearer not-a-real-jwt-at-all"},
                )

        assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# GET /auth/me must still 401 with an expired bearer
# ---------------------------------------------------------------------------

class TestMeStillRequiresValidAuth:
    def test_me_401s_with_expired_bearer(self):
        main = _reload_main_app("dual")
        expired_bearer = _make_supabase_jwt(expired=True)

        client = TestClient(main.app)
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {expired_bearer}"})

        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /auth/update-password must still require valid auth
# ---------------------------------------------------------------------------

class TestUpdatePasswordStillRequiresValidAuth:
    def test_update_password_401s_with_expired_bearer(self):
        main = _reload_main_app("dual")
        expired_bearer = _make_supabase_jwt(expired=True)

        client = TestClient(main.app)
        resp = client.post(
            "/auth/update-password",
            json={"new_password": "SuperSecret99"},
            headers={"Authorization": f"Bearer {expired_bearer}"},
        )

        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Other public auth endpoints + /health must also proceed past the
# middleware despite a bad bearer (handler-level logic still applies).
# ---------------------------------------------------------------------------

class TestOtherPublicEndpointsProceedDespiteBadBearer:
    def test_login_proceeds_to_handler_despite_expired_bearer(self):
        main = _reload_main_app("dual")
        expired_bearer = _make_supabase_jwt(expired=True)

        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.json.return_value = {"message": "Invalid credentials"}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(main.app)
            resp = client.post(
                "/auth/login",
                json={"email": "user@example.com", "password": "whatever123"},
                headers={"Authorization": f"Bearer {expired_bearer}"},
            )

        # 400 (from the mocked Supabase call), NOT 401 from the middleware —
        # proves the handler was reached despite the bad bearer.
        assert resp.status_code == 400
        mock_client.post.assert_called_once()

    def test_signup_proceeds_to_handler_despite_expired_bearer(self):
        main = _reload_main_app("dual")
        expired_bearer = _make_supabase_jwt(expired=True)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "a.b.c",
            "refresh_token": "supabase-rt",
            "token_type": "bearer",
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("routes.auth_routes.get_redis", return_value=_fake_redis()):
            with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
                MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

                client = TestClient(main.app)
                resp = client.post(
                    "/auth/signup",
                    json={"email": "new@example.com", "password": "whatever123"},
                    headers={"Authorization": f"Bearer {expired_bearer}"},
                )

        assert resp.status_code == 200
        mock_client.post.assert_called_once()

    def test_reset_password_proceeds_to_handler_despite_expired_bearer(self):
        main = _reload_main_app("dual")
        expired_bearer = _make_supabase_jwt(expired=True)

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("routes.auth_routes.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client = TestClient(main.app)
            resp = client.post(
                "/auth/reset-password",
                json={"email": "user@example.com"},
                headers={"Authorization": f"Bearer {expired_bearer}"},
            )

        assert resp.status_code == 200
        mock_client.post.assert_called_once()

    def test_health_proceeds_despite_expired_bearer(self):
        main = _reload_main_app("dual")
        expired_bearer = _make_supabase_jwt(expired=True)

        client = TestClient(main.app)
        resp = client.get("/health", headers={"Authorization": f"Bearer {expired_bearer}"})

        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
