"""
FastAPI auth routes powered by Supabase.

These routes proxy to the Supabase Auth API using the service key,
so the frontend never needs the service key directly.

Rate limits (Redis-backed sliding-window, falls back to in-memory if Redis unavailable):
  POST /auth/login   → 5 requests / 60s per IP
  POST /auth/signup  → 3 requests / 60s per IP

Refresh token rotation (TODO-403):
  - Opaque UUID refresh tokens stored in Redis (7-day TTL)
  - /auth/refresh validates + rotates the opaque token
  - /auth/logout revokes the opaque token from Redis
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from threading import Lock
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr

from config.redis_config import get_redis, REDIS_URL
from config.supabase_config import SUPABASE_SERVICE_KEY, SUPABASE_URL

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Shared HTTP client helper (TODO-600)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _http_client(request: Request):
    """
    Yield the shared httpx.AsyncClient from app.state (set by lifespan), or
    fall back to creating a per-request client when running in test mode
    (i.e., no lifespan context / app.state.http_client not configured).

    This keeps existing tests working without modification while giving
    production code a connection-pooled client.
    """
    shared = getattr(request.app.state, "http_client", None)
    if shared is not None:
        yield shared
    else:
        async with httpx.AsyncClient() as client:
            yield client

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REFRESH_TOKEN_TTL = 7 * 24 * 3600  # 7 days in seconds
REFRESH_TOKEN_PREFIX = "rt:"        # Redis key prefix for opaque refresh tokens

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def _build_rate_limiter(max_calls: int, window_seconds: int):
    """
    Return a sliding-window rate-limit checker function.

    Uses Redis (limits library) when available; falls back to an
    in-memory sliding window when Redis is unreachable.

    The returned callable: check(key: str) -> None
    Raises HTTP 429 on limit exceeded.
    """
    # --- Try to build a Redis-backed limiter ---
    r = get_redis()
    if r is not None:
        try:
            from limits import parse as parse_limit
            from limits.storage import RedisStorage
            from limits.strategies import SlidingWindowRateLimiter

            from config.redis_config import REDIS_URL
            storage = RedisStorage(REDIS_URL)
            limiter = SlidingWindowRateLimiter(storage)
            limit_item = parse_limit(f"{max_calls} per {window_seconds} second")

            def _redis_check(key: str) -> None:
                if not limiter.hit(limit_item, "rl", key):
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=(
                            f"Rate limit exceeded: max {max_calls} requests "
                            f"per {window_seconds}s. Try again later."
                        ),
                        headers={"Retry-After": str(window_seconds)},
                    )

            logger.info(
                "Rate limiter using Redis (max=%d, window=%ds)", max_calls, window_seconds
            )
            return _redis_check
        except Exception as exc:
            logger.warning("Could not init Redis rate limiter (%s); using in-memory", exc)

    # --- In-memory fallback ---
    logger.info(
        "Rate limiter using in-memory fallback (max=%d, window=%ds)", max_calls, window_seconds
    )
    _calls: dict[str, list[float]] = defaultdict(list)
    _lock = Lock()

    def _memory_check(key: str) -> None:
        now = time.monotonic()
        cutoff = now - window_seconds
        with _lock:
            _calls[key] = [t for t in _calls[key] if t > cutoff]
            if len(_calls[key]) >= max_calls:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=(
                        f"Rate limit exceeded: max {max_calls} requests "
                        f"per {window_seconds}s. Try again later."
                    ),
                    headers={"Retry-After": str(window_seconds)},
                )
            _calls[key].append(now)

    return _memory_check


# ---------------------------------------------------------------------------
# Backward-compat shim objects for older tests that access ._calls directly.
# These wrap the in-memory fallback's shared _calls dict so tests can reset it.
# ---------------------------------------------------------------------------

class _LimiterShim:
    """Thin wrapper so test_security.py can do limiter._calls.clear()."""

    def __init__(self, check_fn, calls_dict):
        self._check = check_fn
        self._calls = calls_dict

    def check(self, key: str) -> None:
        self._check(key)


# Build in-memory limiters that are exposed for legacy tests
_login_calls: dict[str, list[float]] = defaultdict(list)
_signup_calls: dict[str, list[float]] = defaultdict(list)
_login_lock = Lock()
_signup_lock = Lock()


def _make_shim_check(calls, lock, max_calls, window_seconds):
    def _check(key: str) -> None:
        now = time.monotonic()
        cutoff = now - window_seconds
        with lock:
            calls[key] = [t for t in calls[key] if t > cutoff]
            if len(calls[key]) >= max_calls:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=(
                        f"Rate limit exceeded: max {max_calls} requests "
                        f"per {window_seconds}s. Try again later."
                    ),
                    headers={"Retry-After": str(window_seconds)},
                )
            calls[key].append(now)
    return _check


def _redis_or_memory_check(calls, lock, max_calls, window_seconds):
    """
    Return a check function that tries Redis first, falls back to in-memory.
    This enables cross-replica rate limiting when Redis is available.
    """
    _memory_check = _make_shim_check(calls, lock, max_calls, window_seconds)

    def _check(key: str) -> None:
        r = get_redis()
        if r is not None:
            try:
                from limits import parse as parse_limit
                from limits.storage import RedisStorage
                from limits.strategies import SlidingWindowRateLimiter
                storage = RedisStorage(REDIS_URL)
                limiter = SlidingWindowRateLimiter(storage)
                limit_item = parse_limit(f"{max_calls} per {window_seconds} second")
                if not limiter.hit(limit_item, "rl", key):
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=(
                            f"Rate limit exceeded: max {max_calls} requests "
                            f"per {window_seconds}s. Try again later."
                        ),
                        headers={"Retry-After": str(window_seconds)},
                    )
                return
            except HTTPException:
                raise
            except Exception:
                pass  # Redis path failed, fall through to in-memory
        _memory_check(key)

    return _check


_login_limiter = _LimiterShim(
    _redis_or_memory_check(_login_calls, _login_lock, max_calls=5, window_seconds=60),
    _login_calls,
)
_signup_limiter = _LimiterShim(
    _redis_or_memory_check(_signup_calls, _signup_lock, max_calls=3, window_seconds=60),
    _signup_calls,
)


def _client_ip(request: Request) -> str:
    """Extract real client IP (handles X-Forwarded-For from Railway/nginx)."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Opaque refresh token helpers (TODO-403)
# ---------------------------------------------------------------------------

def _generate_opaque_token() -> str:
    """Generate a random opaque refresh token."""
    return str(uuid.uuid4())


def _store_opaque_token(opaque_token: str, supabase_refresh_token: str) -> None:
    """
    Store opaque → supabase_refresh_token mapping in Redis (TTL = 7 days).
    Falls back to no-op if Redis is unavailable (Supabase handles revocation natively).
    """
    r = get_redis()
    if r is None:
        return
    key = f"{REFRESH_TOKEN_PREFIX}{opaque_token}"
    r.setex(key, REFRESH_TOKEN_TTL, supabase_refresh_token)


def _consume_opaque_token(opaque_token: str) -> Optional[str]:
    """
    Atomically retrieve and delete an opaque token from Redis.
    Returns the associated Supabase refresh token, or None if not found / Redis down.
    """
    r = get_redis()
    if r is None:
        # No Redis — pass the opaque token through as-is (Supabase will reject invalid ones)
        return opaque_token

    key = f"{REFRESH_TOKEN_PREFIX}{opaque_token}"
    # GETDEL atomically returns and removes the key (Redis ≥ 6.2)
    try:
        value = r.getdel(key)
    except Exception:
        # Older Redis — fall back to GET + DEL
        value = r.get(key)
        if value:
            r.delete(key)
    return value  # None if token doesn't exist (already used or expired)


def _revoke_opaque_token(opaque_token: str) -> bool:
    """
    Delete an opaque token from Redis (logout / revocation).
    Returns True if the token existed, False otherwise.
    """
    r = get_redis()
    if r is None:
        return True  # No Redis, nothing to revoke
    key = f"{REFRESH_TOKEN_PREFIX}{opaque_token}"
    return bool(r.delete(key))


def _wrap_with_opaque_token(supabase_response: dict) -> dict:
    """
    Replace the Supabase refresh_token in the response with an opaque one.
    Stores the mapping in Redis.  Returns the modified response.
    """
    sb_refresh = supabase_response.get("refresh_token")
    if not sb_refresh:
        return supabase_response

    opaque = _generate_opaque_token()
    _store_opaque_token(opaque, sb_refresh)

    result = dict(supabase_response)
    result["refresh_token"] = opaque
    return result


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class SignupRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    email: EmailStr
    password: str
    first_name: str = ""
    last_name: str = ""
    organization_id: int | None = None


class LoginRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    refresh_token: str


class LogoutRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    refresh_token: str | None = None


class InviteRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    email: EmailStr
    organization_id: int
    role: str = "viewer"


class PasswordResetRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    email: EmailStr


class PasswordUpdateRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    new_password: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _supabase_headers(*, service: bool = False, access_token: str | None = None):
    h = {
        "apikey": SUPABASE_SERVICE_KEY,
        "Content-Type": "application/json",
    }
    if service:
        h["Authorization"] = f"Bearer {SUPABASE_SERVICE_KEY}"
    elif access_token:
        h["Authorization"] = f"Bearer {access_token}"
    return h


def _extract_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth:
        raise HTTPException(status_code=401, detail="Missing token")
    return auth.split(" ")[-1]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/signup")
async def signup(body: SignupRequest, request: Request):
    """Register a new user via Supabase Auth."""
    _signup_limiter.check(_client_ip(request))
    async with _http_client(request) as client:
        resp = await client.post(
            f"{SUPABASE_URL}/auth/v1/signup",
            headers=_supabase_headers(service=True),
            json={
                "email": body.email,
                "password": body.password,
                "data": {
                    "first_name": body.first_name,
                    "last_name": body.last_name,
                },
                "app_metadata": {
                    "organization_id": body.organization_id,
                    "role": "viewer",
                },
            },
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())
    return _wrap_with_opaque_token(resp.json())


@router.post("/login")
async def login(body: LoginRequest, request: Request):
    """Authenticate and receive tokens (refresh token is opaque UUID)."""
    _login_limiter.check(_client_ip(request))
    async with _http_client(request) as client:
        resp = await client.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
            headers=_supabase_headers(),
            json={"email": body.email, "password": body.password},
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())
    return _wrap_with_opaque_token(resp.json())


@router.post("/refresh")
async def refresh(body: RefreshRequest, request: Request):
    """
    Rotate refresh token.

    Validates the opaque refresh token from Redis, exchanges the underlying
    Supabase token for a new access+refresh pair, revokes the old opaque
    token, and issues a new opaque refresh token.
    """
    opaque_token = body.refresh_token.strip()

    # Consume (validate + delete) the opaque token
    supabase_refresh = _consume_opaque_token(opaque_token)
    if supabase_refresh is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    async with _http_client(request) as client:
        resp = await client.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=refresh_token",
            headers=_supabase_headers(),
            json={"refresh_token": supabase_refresh},
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return _wrap_with_opaque_token(resp.json())


@router.post("/logout")
async def logout(request: Request, body: LogoutRequest | None = None):
    """
    Sign out: revoke opaque refresh token from Redis and invalidate Supabase session.
    The opaque refresh_token can be passed in the request body OR the Authorization
    header is used to call Supabase logout.
    """
    # Revoke opaque token if provided
    if body and body.refresh_token:
        _revoke_opaque_token(body.refresh_token.strip())

    # Also call Supabase logout to invalidate the access token server-side
    token = request.headers.get("Authorization", "").split(" ")[-1]
    if token:
        try:
            async with _http_client(request) as client:
                await client.post(
                    f"{SUPABASE_URL}/auth/v1/logout",
                    headers=_supabase_headers(access_token=token),
                )
        except Exception as exc:
            logger.warning("Supabase logout call failed: %s", exc)

    return {"detail": "Logged out"}


@router.get("/me")
async def me(request: Request):
    """Return current user info from the middleware-populated state."""
    user = getattr(request.state, "user", None)
    if user is None or not user.is_authenticated:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user.model_dump(by_alias=True)


def _get_caller_role(request: Request) -> str:
    """
    Extract the caller's role from the Supabase JWT claims attached by middleware.
    Falls back to an empty string if claims are unavailable.
    Role is stored in app_metadata.role within the JWT.
    """
    claims = getattr(request.state, "supabase_claims", None)
    if claims:
        return claims.get("app_metadata", {}).get("role", "")
    return ""


@router.post("/invite-to-org")
async def invite_to_org(body: InviteRequest, request: Request):
    """
    Invite a user to an organization (admin-only).
    Creates a Supabase user with pre-set org metadata.

    Requires the caller to be authenticated AND have the 'admin' role
    in their Supabase app_metadata.
    """
    caller = getattr(request.state, "user", None)
    if not caller or not caller.is_authenticated:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # SECURITY: enforce admin role — any authenticated user must NOT be able to invite
    caller_role = _get_caller_role(request)
    if caller_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required to invite users to an organization",
        )

    async with _http_client(request) as client:
        # Use admin API to create / invite
        resp = await client.post(
            f"{SUPABASE_URL}/auth/v1/admin/generate_link",
            headers=_supabase_headers(service=True),
            json={
                "type": "invite",
                "email": body.email,
                "data": {},
                "redirect_to": f"{SUPABASE_URL}",
            },
        )
        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.json())

        result = resp.json()
        user_id = result.get("id")

        # Set org metadata on the new user
        if user_id:
            await client.put(
                f"{SUPABASE_URL}/auth/v1/admin/users/{user_id}",
                headers=_supabase_headers(service=True),
                json={
                    "app_metadata": {
                        "organization_id": body.organization_id,
                        "role": body.role,
                    }
                },
            )

    return {"detail": "Invitation sent", "email": body.email}


@router.post("/reset-password")
async def reset_password(body: PasswordResetRequest, request: Request):
    """
    Trigger a Supabase password-reset email.

    Always returns 200 to prevent email enumeration attacks.
    """
    try:
        async with _http_client(request) as client:
            await client.post(
                f"{SUPABASE_URL}/auth/v1/recover",
                headers=_supabase_headers(),
                json={"email": body.email},
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("reset_password: Supabase call failed: %s", exc)

    # Always 200 — never reveal whether the account exists
    return {"message": "If an account exists, a reset email has been sent."}


@router.post("/update-password")
async def update_password(body: PasswordUpdateRequest, request: Request):
    """
    Authenticated user changes their password.

    Requires a valid Bearer token in the Authorization header.
    Password must be at least 8 characters.
    """
    user = getattr(request.state, "user", None)
    if not user or not user.is_authenticated:
        raise HTTPException(status_code=401, detail="Authentication required")

    if len(body.new_password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")

    access_token = _extract_token(request)

    async with _http_client(request) as client:
        resp = await client.put(
            f"{SUPABASE_URL}/auth/v1/user",
            headers=_supabase_headers(access_token=access_token),
            json={"password": body.new_password},
        )

    if resp.status_code >= 400:
        raise HTTPException(status_code=400, detail="Password update failed")

    logger.info("update_password: password changed for user %s", getattr(user, "sub", "unknown"))
    return {"message": "Password updated successfully"}
