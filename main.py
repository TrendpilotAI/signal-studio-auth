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
from middleware.supabase_auth_middleware import supabase_auth_middleware
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

app.add_middleware(SecurityHeadersMiddleware)

# Populate request.state.user on every request (MIGRATION_GUIDE.md, Phase 2)
# so this service authenticates correctly when run standalone, not just as
# a library consumed by another FastAPI app that wires the middleware itself.
app.middleware("http")(supabase_auth_middleware)

# CORS (biggest deployment blocker per BRAINSTORM.md): the frontend runs on
# a different origin than this API, so without CORS every browser request
# is silently rejected. ALLOWED_ORIGINS is a comma-separated allowlist;
# defaults to the local frontend dev server.
_allowed_origins = [
    origin.strip()
    for origin in os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(router)


@app.get("/health")
async def health():
    return {"status": "ok"}
