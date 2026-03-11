"""Tests for SecurityHeadersMiddleware and the app-wide final header policy."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from middleware.security_headers import SECURITY_HEADERS, SecurityHeadersMiddleware


@pytest.fixture
def app_with_headers():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/test")
    async def test_endpoint():
        return {"ok": True}

    return app


@pytest.fixture
def client(app_with_headers):
    return TestClient(app_with_headers)


def test_hsts_header(client):
    resp = client.get("/test")
    assert "max-age=31536000" in resp.headers["strict-transport-security"]
    assert "includeSubDomains" in resp.headers["strict-transport-security"]


def test_x_frame_options(client):
    resp = client.get("/test")
    assert resp.headers["x-frame-options"] == "DENY"


def test_x_content_type_options(client):
    resp = client.get("/test")
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_referrer_policy(client):
    resp = client.get("/test")
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"


def test_csp_frame_ancestors(client):
    resp = client.get("/test")
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]


def test_permissions_policy(client):
    resp = client.get("/test")
    assert "camera=()" in resp.headers["permissions-policy"]


def test_xss_protection(client):
    resp = client.get("/test")
    assert resp.headers["x-xss-protection"] == "1; mode=block"


def test_security_headers_policy_is_centralized():
    assert SECURITY_HEADERS == {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; form-action 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
        "X-XSS-Protection": "1; mode=block",
    }


def test_main_app_applies_exact_final_header_policy(monkeypatch):
    monkeypatch.setenv("SUPABASE_JWT_SECRET", "test-secret-at-least-32-chars-long!!")
    monkeypatch.setenv("SUPABASE_URL", "http://localhost:54321")
    monkeypatch.setenv("SUPABASE_SERVICE_KEY", "test-service-key")
    monkeypatch.setenv("AUTH_SECRET_KEY", "test-secret-at-least-32-chars-long!!")
    monkeypatch.setenv("AUTH_MODE", "supabase")

    sys.modules.pop("config.supabase_config", None)
    sys.modules.pop("routes.auth_routes", None)
    sys.modules.pop("main", None)

    main = importlib.import_module("main")

    with TestClient(main.app) as client:
        resp = client.get("/health")

    for header, expected in SECURITY_HEADERS.items():
        actual_values = resp.headers.get_list(header)
        assert actual_values == [expected], f"{header} was duplicated or downgraded: {actual_values}"

    assert resp.headers["content-security-policy"] == SECURITY_HEADERS["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert "form-action 'self'" in resp.headers["content-security-policy"]
    assert resp.headers["strict-transport-security"].endswith("preload")
    assert resp.headers["x-frame-options"] == "DENY"
