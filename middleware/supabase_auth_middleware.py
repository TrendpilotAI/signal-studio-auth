"""
Supabase Auth Middleware for Signal Builder Backend.

Drop-in replacement for core.middlewares.auth_middleware.
Supports three modes via AUTH_MODE env var:
  - "supabase"     → Only accept Supabase JWTs
  - "forwardlane"  → Only accept legacy ForwardLane JWTs (original behavior)
  - "dual"         → Try Supabase first, fall back to ForwardLane
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

import jwt as pyjwt
from fastapi import Request, status
from fastapi.responses import JSONResponse

from config.supabase_config import (
    AUTH_MODE,
    AuthMode,
    SUPABASE_JWT_ALGORITHM,
    SUPABASE_JWT_AUDIENCE,
    SUPABASE_JWT_SECRET,
)
from mapping.user_mapping import supabase_claims_to_user_dict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# These imports are deferred / optional so the module works even when the
# legacy codebase isn't on sys.path (e.g. during tests).
# ---------------------------------------------------------------------------
_legacy_available: bool = False

try:
    from apps.web_services.forwardlane import ForwardlaneApiService  # type: ignore
    from core.auth.auth_token import AuthToken  # type: ignore
    from core.auth.schemas import AnonymousUser, User  # type: ignore

    _legacy_available = True
except ImportError:
    # Provide lightweight stand-ins so the middleware can run standalone.
    from middleware._compat import AnonymousUser, User  # type: ignore


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _verify_supabase_jwt(token: str) -> dict[str, Any]:
    """Verify a Supabase-issued JWT locally using PyJWT. Returns decoded claims."""
    return pyjwt.decode(
        token,
        SUPABASE_JWT_SECRET,
        algorithms=[SUPABASE_JWT_ALGORITHM],
        audience=SUPABASE_JWT_AUDIENCE,
    )


def _is_supabase_token(payload: dict[str, Any]) -> bool:
    """Heuristic: Supabase tokens have 'aud' == 'authenticated' and 'sub' is a UUID."""
    aud = payload.get("aud")
    sub = str(payload.get("sub", ""))
    return aud == "authenticated" and len(sub) == 36 and "-" in sub


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

AUTHORIZATION_HEADER = "Authorization"

# Endpoints that must remain reachable even when the caller's Authorization
# header is missing, expired, or otherwise invalid — because the handler
# either doesn't require auth at all, or (in the case of /auth/refresh)
# authenticates via the *request body* rather than the bearer token.
#
# Without this, a client that always attaches its (possibly stale) access
# token gets 401'd by this middleware before /auth/refresh ever gets a
# chance to use the body's refresh token to mint a new session (P2).
#
# Handler-level auth still applies where it exists (e.g. /auth/me,
# /auth/update-password are NOT in this set and continue to require a
# valid bearer token).
PUBLIC_PATHS: frozenset[str] = frozenset({
    "/auth/login",
    "/auth/signup",
    "/auth/refresh",
    "/auth/reset-password",
    "/health",
})


def _is_public_path(path: str) -> bool:
    return path in PUBLIC_PATHS


async def supabase_auth_middleware(request: Request, call_next: Callable):
    """Auth middleware supporting Supabase, ForwardLane, or dual mode."""

    optional = _is_public_path(request.url.path)

    if AUTHORIZATION_HEADER not in request.headers:
        request.state.user = AnonymousUser()
        return await call_next(request)

    raw = request.headers[AUTHORIZATION_HEADER]
    token = raw.split(" ")[-1]

    mode = AUTH_MODE

    # --- Supabase-only ---
    if mode == AuthMode.SUPABASE:
        return await _handle_supabase(token, request, call_next, optional=optional)

    # --- ForwardLane-only ---
    if mode == AuthMode.FORWARDLANE:
        return await _handle_forwardlane(token, request, call_next, optional=optional)

    # --- Dual mode: try Supabase first, fall back to ForwardLane ---
    try:
        # Peek at the unverified payload to decide which path to take
        unverified = pyjwt.decode(token, options={"verify_signature": False})
        if _is_supabase_token(unverified):
            return await _handle_supabase(token, request, call_next, optional=optional)
    except Exception:
        pass

    return await _handle_forwardlane(token, request, call_next, optional=optional)


async def _handle_supabase(
    token: str, request: Request, call_next: Callable, optional: bool = False
):
    try:
        claims = _verify_supabase_jwt(token)
    except pyjwt.ExpiredSignatureError:
        if optional:
            request.state.user = AnonymousUser()
            return await call_next(request)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Token expired"},
        )
    except pyjwt.InvalidTokenError as exc:
        logger.warning("Supabase JWT invalid: %s", exc)
        if optional:
            request.state.user = AnonymousUser()
            return await call_next(request)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Invalid JWT token"},
        )

    user_dict = supabase_claims_to_user_dict(claims)
    request.state.user = User(**user_dict)
    # Attach raw claims for downstream use (e.g. org isolation)
    request.state.supabase_claims = claims
    return await call_next(request)


async def _handle_forwardlane(
    token: str, request: Request, call_next: Callable, optional: bool = False
):
    if not _legacy_available:
        if optional:
            request.state.user = AnonymousUser()
            return await call_next(request)
        return JSONResponse(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            content={"detail": "ForwardLane auth not available in this deployment"},
        )

    try:
        await ForwardlaneApiService.verify_jwt_token(token)
    except Exception as exc:
        if optional:
            request.state.user = AnonymousUser()
            return await call_next(request)
        status_code = getattr(exc, "status_code", 500)
        if status_code == status.HTTP_400_BAD_REQUEST:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid JWT token"},
            )
        return JSONResponse(
            status_code=status.HTTP_424_FAILED_DEPENDENCY,
            content={"detail": "Error while verification"},
        )

    request.state.user = User(**AuthToken.get_unverified_jwt_payload(token))
    return await call_next(request)
