"""
signal-studio-auth — FastAPI application entry point.

Lifespan manages a shared httpx.AsyncClient connection pool (TODO-600).
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from middleware.security_headers import SecurityHeadersMiddleware
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

# ---------------------------------------------------------------------------
# CORS — TODO-826
# Set CORS_ALLOWED_ORIGINS to a comma-separated list of allowed origins.
# Example: CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
# ---------------------------------------------------------------------------
CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

app.add_middleware(SecurityHeadersMiddleware)
app.include_router(router)


@app.get("/health")
async def health():
    return {"status": "ok"}
