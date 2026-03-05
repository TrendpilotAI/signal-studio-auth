"""
Tests for TODO-356: require_role() FastAPI RBAC dependency.

Covers:
- Unauthenticated request → 401
- Authenticated with wrong role → 403
- Authenticated with correct role → 200
- Multiple allowed roles (any one passes)
- Role stored in app_metadata (primary) and user_metadata (fallback)
- require_role() with no args raises ValueError at definition time
- Case-insensitive role matching
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from middleware._compat import AnonymousUser, User, UserOrganization
from middleware.rbac import require_role


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app(*routes):
    """Build a minimal FastAPI app with provided route functions."""
    app = FastAPI()
    for method, path, handler in routes:
        getattr(app, method)(path)(handler)
    return app


def _mock_user(authenticated: bool = True) -> MagicMock:
    user = MagicMock()
    user.is_authenticated = authenticated
    return user


def _set_state(request: Request, role: str | None = None, authenticated: bool = True):
    """Attach state to a request object."""
    request.state.user = _mock_user(authenticated)
    if role is not None:
        request.state.supabase_claims = {
            "app_metadata": {"role": role}
        }
    else:
        request.state.supabase_claims = None


# ---------------------------------------------------------------------------
# Test App
# ---------------------------------------------------------------------------

app = FastAPI()


@app.get("/admin-only", dependencies=[require_role("admin")])
async def admin_only(request: Request):
    return {"ok": True}


@app.get("/multi-role", dependencies=[require_role("admin", "org_manager")])
async def multi_role(request: Request):
    return {"ok": True}


@app.get("/case-insensitive", dependencies=[require_role("Admin")])
async def case_insensitive_route(request: Request):
    return {"ok": True}


# Middleware that sets request.state based on custom headers (for testing)
@app.middleware("http")
async def inject_state(request: Request, call_next):
    role = request.headers.get("X-Test-Role", "")
    auth = request.headers.get("X-Test-Auth", "1")

    user = _mock_user(authenticated=(auth == "1"))
    request.state.user = user

    if role:
        request.state.supabase_claims = {"app_metadata": {"role": role}}
    else:
        request.state.supabase_claims = None

    return await call_next(request)


client = TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRequireRoleUnauthenticated:
    def test_no_auth_header_returns_401(self):
        resp = client.get("/admin-only", headers={"X-Test-Auth": "0"})
        assert resp.status_code == 401

    def test_401_detail(self):
        resp = client.get("/admin-only", headers={"X-Test-Auth": "0"})
        assert "Authentication required" in resp.json()["detail"]


class TestRequireRoleWrongRole:
    def test_viewer_cannot_access_admin_only(self):
        resp = client.get("/admin-only", headers={"X-Test-Role": "viewer"})
        assert resp.status_code == 403

    def test_403_detail_includes_required_role(self):
        resp = client.get("/admin-only", headers={"X-Test-Role": "viewer"})
        body = resp.json()["detail"]
        assert "admin" in body

    def test_empty_role_returns_403(self):
        resp = client.get("/admin-only")  # no role header
        assert resp.status_code == 403


class TestRequireRoleCorrectRole:
    def test_admin_can_access_admin_only(self):
        resp = client.get("/admin-only", headers={"X-Test-Role": "admin"})
        assert resp.status_code == 200

    def test_admin_can_access_multi_role_route(self):
        resp = client.get("/multi-role", headers={"X-Test-Role": "admin"})
        assert resp.status_code == 200

    def test_org_manager_can_access_multi_role_route(self):
        resp = client.get("/multi-role", headers={"X-Test-Role": "org_manager"})
        assert resp.status_code == 200

    def test_viewer_cannot_access_multi_role_route(self):
        resp = client.get("/multi-role", headers={"X-Test-Role": "viewer"})
        assert resp.status_code == 403


class TestRequireRoleCaseInsensitive:
    def test_uppercase_role_header_accepted(self):
        resp = client.get("/case-insensitive", headers={"X-Test-Role": "ADMIN"})
        assert resp.status_code == 200

    def test_mixed_case_role_header_accepted(self):
        resp = client.get("/case-insensitive", headers={"X-Test-Role": "Admin"})
        assert resp.status_code == 200


class TestRequireRoleDefinitionErrors:
    def test_no_args_raises_value_error(self):
        with pytest.raises(ValueError, match="at least one role"):
            require_role()


class TestGetCallerRole:
    """Unit tests for the _get_caller_role helper."""

    def test_returns_app_metadata_role(self):
        from middleware.rbac import _get_caller_role

        req = MagicMock()
        req.state.supabase_claims = {"app_metadata": {"role": "admin"}}
        assert _get_caller_role(req) == "admin"

    def test_falls_back_to_user_metadata(self):
        from middleware.rbac import _get_caller_role

        req = MagicMock()
        req.state.supabase_claims = {
            "app_metadata": {},
            "user_metadata": {"role": "org_manager"},
        }
        assert _get_caller_role(req) == "org_manager"

    def test_returns_empty_string_when_no_claims(self):
        from middleware.rbac import _get_caller_role

        req = MagicMock()
        req.state.supabase_claims = None
        assert _get_caller_role(req) == ""

    def test_returns_empty_string_when_no_claims_attr(self):
        from middleware.rbac import _get_caller_role

        req = MagicMock()
        # state exists but supabase_claims is absent
        del req.state.supabase_claims
        req.state.supabase_claims = None
        assert _get_caller_role(req) == ""
