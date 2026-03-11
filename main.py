"""
signal-studio-auth — FastAPI application entry point.

Lifespan manages a shared httpx.AsyncClient connection pool (TODO-600) and
runs startup validation to fail fast when required env vars are absent (#834).
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from middleware.security_headers import SecurityHeadersMiddleware
from routes.auth_routes import router

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Required environment variables — checked at startup (#834).
# ---------------------------------------------------------------------------
_REQUIRED_ENV_VARS: list[str] = [
    "SUPABASE_URL",
    "SUPABASE_SERVICE_KEY",
    "SUPABASE_JWT_SECRET",
]


def validate_required_env_vars() -> None:
    """
    Fail fast if any required environment variable is missing.

    Checks SUPABASE_URL, SUPABASE_SERVICE_KEY, and SUPABASE_JWT_SECRET.
    Skipped automatically during pytest runs so CI/CD test suites don't
    need to supply production secrets.  Fixes #834.
    """
    is_testing = (
        "pytest" in sys.modules
        or bool(os.environ.get("PYTEST_CURRENT_TEST"))
    )
    if is_testing:
        return

    missing = [var for var in _REQUIRED_ENV_VARS if not os.environ.get(var)]
    if missing:
        raise RuntimeError(
            f"[signal-studio-auth] FATAL: Missing required environment variables: "
            f"{', '.join(missing)}. "
            f"Set these variables before starting the service."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: validate required env vars (#834), then create a shared
    httpx.AsyncClient with connection pooling (TODO-600).
    Shutdown: gracefully close all connections.
    """
    validate_required_env_vars()
    logger.info("Starting up — creating shared httpx connection pool")
    app.state.http_client = httpx.AsyncClient(
        limits=httpx.Limits(
            max_connections=100,
            max_keepalive_connections=20,
            keepalive_expiry=30,
        ),
        timeout=httpx.Timeout(30.0),
    )
    try:
        yield
    finally:
        logger.info("Shutting down — closing shared httpx connection pool")
        await app.state.http_client.aclose()


app = FastAPI(
    title="signal-studio-auth",
    description="Authentication proxy for Signal Studio, powered by Supabase.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)
app.include_router(router)


@app.get("/health")
async def health():
    return {"status": "ok"}
