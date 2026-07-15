"""
Tests for CORS middleware wiring in main.py (BRAINSTORM: "biggest deployment
blocker" — the frontend cannot call this service cross-origin without CORS).

Verifies:
  - Preflight OPTIONS from an allowed origin (ALLOWED_ORIGINS env, comma
    separated, default 'http://localhost:3000') returns the CORS headers.
  - Preflight OPTIONS from a disallowed origin gets no CORS headers.

Run: pytest tests/test_cors.py -v
"""

from __future__ import annotations

import importlib
import os
from unittest.mock import patch

# Set env before importing our modules (existing test-file bootstrap pattern).
os.environ.setdefault("SUPABASE_JWT_SECRET", "test-secret-at-least-32-chars-long!!")
os.environ.setdefault("SUPABASE_URL", "http://localhost:54321")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test-service-key")
os.environ.setdefault("AUTH_MODE", "dual")

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient


def _build_main_app(allowed_origins: str | None = None):
    """
    (Re)import main.py, optionally overriding ALLOWED_ORIGINS, so the
    module-level CORSMiddleware wiring picks up the new value. main.py reads
    ALLOWED_ORIGINS once at import time, so a fresh import/reload per
    scenario is required to exercise different configurations.
    """
    env = {}
    if allowed_origins is not None:
        env["ALLOWED_ORIGINS"] = allowed_origins
    else:
        # Ensure no leftover ALLOWED_ORIGINS from another test/process leaks in.
        env["ALLOWED_ORIGINS"] = ""

    with patch.dict(os.environ, env):
        if allowed_origins is None:
            os.environ.pop("ALLOWED_ORIGINS", None)
        if "main" in sys.modules:
            main = importlib.reload(sys.modules["main"])
        else:
            import main
    return main.app


def _preflight(client: TestClient, origin: str, path: str = "/auth/me"):
    return client.options(
        path,
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
        },
    )


class TestCORSDefaultOrigin:
    """No ALLOWED_ORIGINS set -> defaults to http://localhost:3000."""

    def test_preflight_from_default_allowed_origin_gets_cors_headers(self):
        app = _build_main_app(None)
        client = TestClient(app)
        resp = _preflight(client, "http://localhost:3000")

        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"
        assert resp.headers.get("access-control-allow-credentials") == "true"

    def test_preflight_from_disallowed_origin_gets_no_cors_headers(self):
        app = _build_main_app(None)
        client = TestClient(app)
        resp = _preflight(client, "http://evil.example.com")

        assert "access-control-allow-origin" not in resp.headers


class TestCORSCustomOrigins:
    """ALLOWED_ORIGINS is a comma-separated allowlist."""

    def test_allowed_origin_from_custom_list_gets_cors_headers(self):
        app = _build_main_app("https://app.signalstudio.io,https://staging.signalstudio.io")
        client = TestClient(app)
        resp = _preflight(client, "https://staging.signalstudio.io")

        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == "https://staging.signalstudio.io"

    def test_origin_not_in_custom_list_gets_no_cors_headers(self):
        app = _build_main_app("https://app.signalstudio.io")
        client = TestClient(app)
        resp = _preflight(client, "http://localhost:3000")

        assert "access-control-allow-origin" not in resp.headers


class TestCORSAllowedHeadersAndMethods:
    def test_preflight_allows_authorization_header(self):
        app = _build_main_app(None)
        client = TestClient(app)
        resp = client.options(
            "/auth/me",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        assert resp.status_code == 200
        allow_headers = resp.headers.get("access-control-allow-headers", "").lower()
        assert "authorization" in allow_headers
        assert "content-type" in allow_headers

    def test_preflight_allows_delete_method(self):
        app = _build_main_app(None)
        client = TestClient(app)
        resp = client.options(
            "/auth/me",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "DELETE",
            },
        )
        assert resp.status_code == 200
        allow_methods = resp.headers.get("access-control-allow-methods", "")
        assert "DELETE" in allow_methods
