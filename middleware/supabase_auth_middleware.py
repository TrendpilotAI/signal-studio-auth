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


async def supabase_auth_middleware(request: Request, call_next: Callable):
    """Auth middleware supporting Supabase, ForwardLane, or dual mode."""

    if AUTHORIZATION_HEADER not in request.headers:
        request.state.user = AnonymousUser()
        return await call_next(request)

    raw = request.headers[AUTHORIZATION_HEADER]
    token = raw.split(" ")[-1]

    mode = AUTH_MODE

    # --- Supabase-only ---
    if mode == AuthMode.SUPABASE:
        return await _handle_supabase(token, request, call_next)

    # --- ForwardLane-only ---
    if mode == AuthMode.FORWARDLANE:
        return await _handle_forwardlane(token, request, call_next)

    # --- Dual mode: try Supabase first, fall back to ForwardLane ---
    try:
        # Peek at the unverified payload to decide which path to take
        unverified = pyjwt.decode(token, options={"verify_signature": False})
        if _is_supabase_token(unverified):
            return await _handle_supabase(token, request, call_next)
    except Exception:
        pass

    return await _handle_forwardlane(token, request, call_next)


async def _handle_supabase(token: str, request: Request, call_next: Callable):
    try:
        claims = _verify_supabase_jwt(token)
    except pyjwt.ExpiredSignatureError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Token expired"},
        )
    except pyjwt.InvalidTokenError as exc:
        logger.warning("Supabase JWT invalid: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Invalid JWT token"},
        )

    user_dict = supabase_claims_to_user_dict(claims)
    request.state.user = User(**user_dict)
    # Attach raw claims for downstream use (e.g. org isolation)
    request.state.supabase_claims = claims
    return await call_next(request)


async def _handle_forwardlane(token: str, request: Request, call_next: Callable):
    if not _legacy_available:
        return JSONResponse(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            content={"detail": "ForwardLane auth not available in this deployment"},
        )

    try:
        await ForwardlaneApiService.verify_jwt_token(token)
    except Exception as exc:
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
