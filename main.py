"""
signal-studio-auth — FastAPI application entry point.

Lifespan manages a shared httpx.AsyncClient connection pool (TODO-600).
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

from routes.auth_routes import router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: create a shared httpx.AsyncClient with connection pooling.
    Shutdown: gracefully close all connections.

    TODO-600: replaces per-request httpx.AsyncClient creation (6+ TCP opens/request).
    """
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

app.include_router(router)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """SSA-002: Add security headers to every response."""
    response: Response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-XSS-Protection"] = "0"
    return response


@app.get("/health")
async def health():
    return {"status": "ok"}
