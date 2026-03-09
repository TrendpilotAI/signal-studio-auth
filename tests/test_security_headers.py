"""Tests for SecurityHeadersMiddleware."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from middleware.security_headers import SecurityHeadersMiddleware


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
