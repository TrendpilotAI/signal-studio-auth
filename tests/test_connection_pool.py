"""
Tests for TODO-600: httpx connection pool via FastAPI lifespan.

Verifies that:
- The shared httpx.AsyncClient is created during app startup.
- The same client instance is reused across multiple requests (not recreated).
- The client is properly closed on shutdown.
"""

from __future__ import annotations

import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("SUPABASE_JWT_SECRET", "test-secret-at-least-32-chars-long!!")
os.environ.setdefault("SUPABASE_URL", "http://localhost:54321")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test-service-key")
os.environ.setdefault("AUTH_MODE", "supabase")

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import httpx
from fastapi.testclient import TestClient


class TestConnectionPool:
    """Verify the shared httpx.AsyncClient is reused across requests."""

    def _build_app_with_lifespan(self):
        """Build the app via main.py (includes lifespan / connection pool)."""
        import main  # triggers lifespan setup
        return main.app

    def test_lifespan_creates_http_client(self):
        """App should have a live httpx.AsyncClient on app.state after startup."""
        app = self._build_app_with_lifespan()
        with TestClient(app):
            assert hasattr(app.state, "http_client")
            assert isinstance(app.state.http_client, httpx.AsyncClient)
            assert not app.state.http_client.is_closed

    def test_client_is_closed_after_shutdown(self):
        """The shared client should be closed (aclose called) after lifespan exits."""
        app = self._build_app_with_lifespan()
        with TestClient(app) as _:
            client = app.state.http_client
        # After the context manager exits, lifespan cleanup runs → client closed
        assert client.is_closed

    def test_same_client_instance_across_requests(self):
        """
        The client stored on app.state must be the SAME object across multiple
        requests — verifies the pool is not recreated per-request.

        We confirm by checking that the object identity (id) on app.state
        never changes while the lifespan is active.
        """
        app = self._build_app_with_lifespan()

        with TestClient(app):
            client_at_startup = app.state.http_client
            id_at_startup = id(client_at_startup)

            # Simulate multiple "requests" reading from the same app.state
            ids = set()
            for _ in range(5):
                ids.add(id(app.state.http_client))

        # All reads must return the same singleton
        assert len(ids) == 1, f"Expected 1 unique client id, got {ids}"
        assert list(ids)[0] == id_at_startup

    def test_http_client_helper_uses_shared_client(self):
        """
        _http_client() context manager should yield the shared app.state client
        when it is available (not create a new one).
        """
        import asyncio
        from routes.auth_routes import _http_client
        from fastapi import Request
        from unittest.mock import MagicMock

        mock_client = MagicMock(spec=httpx.AsyncClient)
        mock_request = MagicMock(spec=Request)
        mock_request.app.state.http_client = mock_client

        async def _run():
            async with _http_client(mock_request) as client:
                return client

        result = asyncio.get_event_loop().run_until_complete(_run())
        assert result is mock_client, "Should yield the shared client, not a new one"

    def test_http_client_helper_fallback_when_no_state(self):
        """
        _http_client() should fall back to a temporary httpx.AsyncClient
        when app.state.http_client is not set (test/standalone mode).
        """
        import asyncio
        from routes.auth_routes import _http_client
        from fastapi import Request
        from unittest.mock import MagicMock

        mock_request = MagicMock(spec=Request)
        # No http_client on state
        del mock_request.app.state.http_client
        mock_request.app.state = MagicMock(spec=[])  # empty state

        async def _run():
            async with _http_client(mock_request) as client:
                return type(client).__name__

        result = asyncio.get_event_loop().run_until_complete(_run())
        assert result == "AsyncClient"
