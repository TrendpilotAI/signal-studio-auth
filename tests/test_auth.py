"""
Tests for Supabase auth middleware, JWT verification, and user mapping.

Run: pytest tests/test_auth.py -v
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import jwt as pyjwt
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

# Set env before importing our modules
os.environ["SUPABASE_JWT_SECRET"] = "test-secret-at-least-32-chars-long!!"
os.environ["SUPABASE_URL"] = "http://localhost:54321"
os.environ["AUTH_MODE"] = "dual"

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from config.supabase_config import AuthMode
from mapping.user_mapping import supabase_claims_to_user_dict, _uuid_to_int
from middleware._compat import User, AnonymousUser

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SECRET = os.environ["SUPABASE_JWT_SECRET"]


def _make_supabase_jwt(
    sub: str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    email: str = "test@example.com",
    org_id: int = 42,
    role: str = "analyst",
    expired: bool = False,
) -> str:
    now = datetime.now(timezone.utc)
    exp = now - timedelta(hours=1) if expired else now + timedelta(hours=1)
    payload = {
        "sub": sub,
        "email": email,
        "aud": "authenticated",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "app_metadata": {
            "organization_id": org_id,
            "organization_name": "TestOrg",
            "organization_vertical": "finance",
            "role": role,
        },
        "user_metadata": {
            "first_name": "Jane",
            "last_name": "Doe",
        },
    }
    return pyjwt.encode(payload, SECRET, algorithm="HS256")


def _make_legacy_jwt(user_id: int = 99, email: str = "legacy@example.com") -> str:
    """Fake a legacy ForwardLane-style JWT (no 'aud' claim)."""
    payload = {
        "user_id": user_id,
        "username": "legacyuser",
        "email": email,
        "organization": {"id": 1, "name": "LegacyCorp", "vertical": "advisory"},
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
    }
    return pyjwt.encode(payload, "legacy-secret", algorithm="HS256")


# ---------------------------------------------------------------------------
# User Mapping Tests
# ---------------------------------------------------------------------------

class TestUserMapping:
    def test_supabase_claims_to_user_dict(self):
        claims = {
            "sub": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "email": "test@example.com",
            "app_metadata": {
                "organization_id": 42,
                "organization_name": "TestOrg",
                "organization_vertical": "finance",
                "legacy_user_id": 100,
            },
            "user_metadata": {"first_name": "Jane", "last_name": "Doe"},
        }
        result = supabase_claims_to_user_dict(claims)
        assert result["user_id"] == 100  # uses legacy_user_id
        assert result["email"] == "test@example.com"
        assert result["organization"]["id"] == 42

    def test_uuid_to_int_deterministic(self):
        uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert _uuid_to_int(uuid) == _uuid_to_int(uuid)
        assert _uuid_to_int(uuid) > 0

    def test_missing_legacy_id_uses_uuid_hash(self):
        claims = {
            "sub": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "email": "new@example.com",
            "app_metadata": {"organization_id": 1},
            "user_metadata": {},
        }
        result = supabase_claims_to_user_dict(claims)
        assert isinstance(result["user_id"], int)
        assert result["user_id"] > 0


# ---------------------------------------------------------------------------
# JWT Verification Tests
# ---------------------------------------------------------------------------

class TestJWTVerification:
    def test_valid_supabase_jwt(self):
        token = _make_supabase_jwt()
        claims = pyjwt.decode(token, SECRET, algorithms=["HS256"], audience="authenticated")
        assert claims["email"] == "test@example.com"
        assert claims["app_metadata"]["organization_id"] == 42

    def test_expired_jwt_raises(self):
        token = _make_supabase_jwt(expired=True)
        with pytest.raises(pyjwt.ExpiredSignatureError):
            pyjwt.decode(token, SECRET, algorithms=["HS256"], audience="authenticated")

    def test_wrong_secret_raises(self):
        token = _make_supabase_jwt()
        with pytest.raises(pyjwt.InvalidSignatureError):
            pyjwt.decode(token, "wrong-secret-but-at-least-32-bytes!!", algorithms=["HS256"], audience="authenticated")


# ---------------------------------------------------------------------------
# Middleware Integration Tests
# ---------------------------------------------------------------------------

def _build_app(auth_mode: str = "dual"):
    from middleware.supabase_auth_middleware import supabase_auth_middleware

    with patch.dict(os.environ, {"AUTH_MODE": auth_mode}):
        # Re-import to pick up new AUTH_MODE
        import importlib
        import config.supabase_config as cfg
        cfg.AUTH_MODE = AuthMode(auth_mode)

        app = FastAPI()

        @app.middleware("http")
        async def mw(request, call_next):
            return await supabase_auth_middleware(request, call_next)

        @app.get("/test")
        async def test_route(request: Request):
            user = request.state.user
            return {
                "authenticated": user.is_authenticated,
                "email": getattr(user, "email", None),
            }

        return app


class TestMiddleware:
    def test_no_auth_header_returns_anonymous(self):
        app = _build_app("supabase")
        client = TestClient(app)
        resp = client.get("/test")
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is False

    def test_valid_supabase_token(self):
        app = _build_app("supabase")
        client = TestClient(app)
        token = _make_supabase_jwt()
        resp = client.get("/test", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is True
        assert resp.json()["email"] == "test@example.com"

    def test_expired_token_returns_401(self):
        app = _build_app("supabase")
        client = TestClient(app)
        token = _make_supabase_jwt(expired=True)
        resp = client.get("/test", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_dual_mode_supabase_token(self):
        app = _build_app("dual")
        client = TestClient(app)
        token = _make_supabase_jwt()
        resp = client.get("/test", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is True


# ---------------------------------------------------------------------------
# Org Isolation Tests
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_different_orgs_get_different_user_objects(self):
        claims_org1 = {
            "sub": "aaaa-bbbb-cccc-dddd-eeee-ffffffff0001",
            "email": "user1@org1.com",
            "app_metadata": {"organization_id": 1, "organization_name": "Org1", "organization_vertical": "fin"},
            "user_metadata": {},
        }
        claims_org2 = {
            "sub": "aaaa-bbbb-cccc-dddd-eeee-ffffffff0002",
            "email": "user2@org2.com",
            "app_metadata": {"organization_id": 2, "organization_name": "Org2", "organization_vertical": "health"},
            "user_metadata": {},
        }
        u1 = supabase_claims_to_user_dict(claims_org1)
        u2 = supabase_claims_to_user_dict(claims_org2)
        assert u1["organization"]["id"] != u2["organization"]["id"]
        assert u1["organization"]["id"] == 1
        assert u2["organization"]["id"] == 2

    def test_org_tenant_schema_name(self):
        from middleware._compat import UserOrganization
        org = UserOrganization(id=42, name="Acme Corp", vertical="finance")
        tenant = org.as_tenant_org()
        assert tenant["schema_name"] == "acme-corp-42"
        assert tenant["external_id"] == 42
