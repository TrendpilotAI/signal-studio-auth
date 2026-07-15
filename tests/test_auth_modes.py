"""
Tests for AUTH_MODE dual-mode switching and standalone wiring (AUDIT-flagged
gaps: dual mode routing was never exercised with a real mode switch, and
nothing verified main.py actually populates request.state.user standalone).

Run: pytest tests/test_auth_modes.py -v
"""

from __future__ import annotations

import importlib
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import jwt as pyjwt
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

# Set env before importing our modules (existing test-file bootstrap pattern).
os.environ.setdefault("SUPABASE_JWT_SECRET", "test-secret-at-least-32-chars-long!!")
os.environ.setdefault("SUPABASE_URL", "http://localhost:54321")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test-service-key")
os.environ.setdefault("AUTH_MODE", "dual")

import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

SUPABASE_SECRET = os.environ["SUPABASE_JWT_SECRET"]


def _make_supabase_jwt(
    sub: str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    email: str = "dual@example.com",
    expired: bool = False,
) -> str:
    """A genuine Supabase-shaped HS256 JWT: aud='authenticated', uuid sub,
    signed with SUPABASE_JWT_SECRET."""
    now = datetime.now(timezone.utc)
    exp = now - timedelta(hours=1) if expired else now + timedelta(hours=1)
    payload = {
        "sub": sub,
        "email": email,
        "aud": "authenticated",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "app_metadata": {
            "organization_id": 7,
            "organization_name": "DualOrg",
            "organization_vertical": "finance",
        },
        "user_metadata": {"first_name": "Dual", "last_name": "User"},
    }
    return pyjwt.encode(payload, SUPABASE_SECRET, algorithm="HS256")


def _make_forwardlane_jwt(user_id: int = 7, email: str = "legacy@example.com") -> str:
    """A ForwardLane-shaped JWT: no 'aud' claim, integer user_id, signed with
    a non-Supabase secret — this is NOT a Supabase token."""
    payload = {
        "user_id": user_id,
        "username": "legacyuser",
        "email": email,
        "organization": {"id": 1, "name": "LegacyCorp", "vertical": "advisory"},
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
    }
    return pyjwt.encode(payload, "legacy-secret-not-supabase", algorithm="HS256")


def _reload_middleware_for_mode(auth_mode: str):
    """
    Force config.supabase_config.AUTH_MODE and middleware.supabase_auth_middleware's
    module-level AUTH_MODE binding to the given mode by reloading both modules
    under a patched environment, then return the freshly bound middleware
    coroutine. Both modules bind AUTH_MODE at import time (`from ... import
    AUTH_MODE`), so a plain attribute assignment on the config module is not
    enough — the middleware module must be reloaded too.
    """
    with patch.dict(os.environ, {"AUTH_MODE": auth_mode}):
        import config.supabase_config as cfg
        importlib.reload(cfg)

        import middleware.supabase_auth_middleware as mw
        importlib.reload(mw)

    return mw.supabase_auth_middleware


def _build_probe_app(auth_mode: str) -> FastAPI:
    """Build a minimal FastAPI app wired with the auth middleware forced into
    the given AUTH_MODE, mirroring the wiring documented in MIGRATION_GUIDE.md."""
    middleware_fn = _reload_middleware_for_mode(auth_mode)

    app = FastAPI()

    @app.middleware("http")
    async def _mw(request, call_next):
        return await middleware_fn(request, call_next)

    @app.get("/probe")
    async def probe(request: Request):
        user = request.state.user
        return {
            "authenticated": user.is_authenticated,
            "email": getattr(user, "email", None),
        }

    return app


# ---------------------------------------------------------------------------
# Dual-mode switching
# ---------------------------------------------------------------------------

class TestDualModeSwitching:
    def test_dual_mode_routes_supabase_shaped_token_to_supabase_path(self):
        app = _build_probe_app("dual")
        client = TestClient(app)
        token = _make_supabase_jwt()

        resp = client.get("/probe", headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        assert resp.json()["authenticated"] is True
        assert resp.json()["email"] == "dual@example.com"

    def test_dual_mode_routes_non_supabase_token_to_forwardlane_path_yields_501(self):
        app = _build_probe_app("dual")
        client = TestClient(app)
        token = _make_forwardlane_jwt()

        resp = client.get("/probe", headers={"Authorization": f"Bearer {token}"})

        # Legacy ForwardLane libs are absent in this standalone deployment,
        # so the middleware's ForwardLane fallback yields 501, not a 401 or
        # a silent pass-through — proving dual mode really did route the
        # non-Supabase-shaped token down the ForwardLane path.
        assert resp.status_code == 501


# ---------------------------------------------------------------------------
# Supabase-only mode
# ---------------------------------------------------------------------------

class TestSupabaseOnlyMode:
    def test_supabase_mode_accepts_supabase_shaped_token(self):
        app = _build_probe_app("supabase")
        client = TestClient(app)
        token = _make_supabase_jwt()

        resp = client.get("/probe", headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        assert resp.json()["authenticated"] is True

    def test_supabase_mode_rejects_forwardlane_shaped_token_outright(self):
        app = _build_probe_app("supabase")
        client = TestClient(app)
        token = _make_forwardlane_jwt()

        resp = client.get("/probe", headers={"Authorization": f"Bearer {token}"})

        # Supabase-only mode never falls back to ForwardLane — a
        # ForwardLane-shaped token fails Supabase JWT verification outright.
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Standalone wiring: main.py itself must populate request.state.user
# ---------------------------------------------------------------------------

class TestMainAppStandaloneWiring:
    def test_get_auth_me_authenticates_via_main_app_directly(self):
        """
        GET /auth/me must work against main.app with no extra wiring from a
        consumer, per MIGRATION_GUIDE.md Phase 2 ("Add the middleware to
        your FastAPI app"). This exercises main.py's own middleware
        registration, not a test-built app.
        """
        # Force dual mode (the documented default) so this test's outcome
        # does not depend on which mode some other test last reloaded.
        _reload_middleware_for_mode("dual")

        with patch.dict(os.environ, {"AUTH_MODE": "dual"}):
            if "main" in sys.modules:
                main = importlib.reload(sys.modules["main"])
            else:
                import main

        client = TestClient(main.app)
        token = _make_supabase_jwt(email="standalone@example.com")

        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        assert resp.json()["email"] == "standalone@example.com"

    def test_get_auth_me_401s_without_a_token_via_main_app(self):
        _reload_middleware_for_mode("dual")

        with patch.dict(os.environ, {"AUTH_MODE": "dual"}):
            if "main" in sys.modules:
                main = importlib.reload(sys.modules["main"])
            else:
                import main

        client = TestClient(main.app)
        resp = client.get("/auth/me")

        assert resp.status_code == 401
