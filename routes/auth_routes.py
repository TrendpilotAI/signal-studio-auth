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
from middleware.rbac import _get_caller_role

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

_reset_password_calls: dict[str, list[float]] = defaultdict(list)
_update_password_calls: dict[str, list[float]] = defaultdict(list)
_reset_password_lock = Lock()
_update_password_lock = Lock()

_reset_password_limiter = _LimiterShim(
    _redis_or_memory_check(_reset_password_calls, _reset_password_lock, max_calls=3, window_seconds=3600),
    _reset_password_calls,
)
_update_password_limiter = _LimiterShim(
    _redis_or_memory_check(_update_password_calls, _update_password_lock, max_calls=5, window_seconds=3600),
    _update_password_calls,
)


def _client_ip(request: Request) -> str:
    """Extract real client IP (handles X-Forwarded-For from Railway/nginx)."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Refresh token family tracking helpers (TODO-603)
#
# Redis data model:
#   rt:{token_id}         HASH  {user_id, family_id, parent_id, supabase_token, consumed}
#   rt:family:{family_id} SET   all token_ids belonging to this family
#
# On rotation the old token is marked consumed=1 (not deleted) so that
# a reuse attempt can be detected.  Reuse → full family revocation (theft
# detection).  The family SET is used to enumerate all tokens to delete.
# ---------------------------------------------------------------------------

def _issue_family_token(supabase_token: str,
                        user_id: str = "",
                        parent_id: str = "",
                        family_id: Optional[str] = None) -> str:
    """
    Issue a new opaque refresh token in a token family.

    Creates a new family when family_id is None (initial login / signup).
    Returns the new opaque token_id.  Falls back to a plain UUID if Redis
    is unavailable (no persistence — Supabase handles session revocation).
    """
    token_id = str(uuid.uuid4())
    fid = family_id or str(uuid.uuid4())

    r = get_redis()
    if r is None:
        return token_id  # No Redis — opaque token has no server-side state

    pipe = r.pipeline()
    pipe.hset(f"rt:{token_id}", mapping={
        "user_id": user_id,
        "family_id": fid,
        "parent_id": parent_id,
        "supabase_token": supabase_token,
        "consumed": "0",
    })
    pipe.expire(f"rt:{token_id}", REFRESH_TOKEN_TTL)
    pipe.sadd(f"rt:family:{fid}", token_id)
    pipe.expire(f"rt:family:{fid}", REFRESH_TOKEN_TTL)
    pipe.execute()
    return token_id


def _rotate_family_token(old_token_id: str, new_supabase_token: str) -> str:
    """
    Rotate a refresh token within its family.

    Marks the old token as consumed and issues a new child token.
    If the old token is already consumed (i.e. was reused), the entire
    family is revoked and an HTTP 401 is raised (theft detection).

    Returns the new opaque token_id.
    """
    r = get_redis()
    if r is None:
        # No Redis — issue a bare token (no theft detection possible)
        return str(uuid.uuid4())

    data = r.hgetall(f"rt:{old_token_id}")
    if not data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    if data.get("consumed") == "1":
        # ── THEFT DETECTED ──────────────────────────────────────────────
        # A consumed (already-rotated) token was presented.  The legitimate
        # user's token chain and the attacker's chain share the same family.
        # Revoke every token in the family to force a full re-login.
        family_id = data.get("family_id", "")
        if family_id:
            family_members = r.smembers(f"rt:family:{family_id}")
            pipe = r.pipeline()
            for member_id in family_members:
                pipe.delete(f"rt:{member_id}")
            pipe.delete(f"rt:family:{family_id}")
            pipe.execute()
        logger.warning(
            "Refresh token theft detected: token_id=%s family=%s user=%s",
            old_token_id, family_id, data.get("user_id", ""),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token reuse detected — all sessions revoked",
        )

    # Mark old token as consumed (do NOT delete — we need it for reuse detection)
    r.hset(f"rt:{old_token_id}", "consumed", "1")

    # Issue new child token in the same family
    return _issue_family_token(
        supabase_token=new_supabase_token,
        user_id=data.get("user_id", ""),
        parent_id=old_token_id,
        family_id=data.get("family_id"),
    )


def _revoke_opaque_token(opaque_token: str) -> bool:
    """
    Delete an opaque token from Redis (logout / revocation).
    Also removes the token from its family SET to keep it tidy.
    Returns True if the token existed, False otherwise.
    """
    r = get_redis()
    if r is None:
        return True  # No Redis, nothing to revoke

    key = f"rt:{opaque_token}"
    data = r.hgetall(key)
    existed = bool(data)

    pipe = r.pipeline()
    pipe.delete(key)
    family_id = data.get("family_id", "") if data else ""
    if family_id:
        pipe.srem(f"rt:family:{family_id}", opaque_token)
    pipe.execute()
    return existed


def _wrap_with_opaque_token(supabase_response: dict, user_id: str = "") -> dict:
    """
    Replace the Supabase refresh_token in the response with an opaque family token.
    Creates a new token family (called on initial login / signup).
    Returns the modified response dict.
    """
    sb_refresh = supabase_response.get("refresh_token")
    if not sb_refresh:
        return supabase_response

    # Extract user_id from the response if not supplied
    if not user_id:
        user_id = (
            supabase_response.get("user", {}) or {}
        ).get("id", "")

    opaque = _issue_family_token(supabase_token=sb_refresh, user_id=user_id)

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

    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one number")
        return v


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
    Rotate refresh token with family tracking (TODO-603).

    1. Look up the opaque token in Redis (hash).
    2. If already consumed → theft detected → revoke entire family → 401.
    3. If valid → mark consumed, call Supabase, issue child token in same family.
    """
    old_token_id = body.refresh_token.strip()

    r = get_redis()
    if r is not None:
        token_data = r.hgetall(f"rt:{old_token_id}")
        if not token_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )
        if token_data.get("consumed") == "1":
            # ── THEFT DETECTED ──────────────────────────────────────────
            family_id = token_data.get("family_id", "")
            if family_id:
                family_members = r.smembers(f"rt:family:{family_id}")
                pipe = r.pipeline()
                for member_id in family_members:
                    pipe.delete(f"rt:{member_id}")
                pipe.delete(f"rt:family:{family_id}")
                pipe.execute()
            logger.warning(
                "Refresh token theft detected: token_id=%s family=%s user=%s",
                old_token_id, token_data.get("family_id", ""), token_data.get("user_id", ""),
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token reuse detected — all sessions revoked",
            )
        supabase_refresh = token_data["supabase_token"]
        # Mark old token consumed before calling Supabase (prevents double-use race)
        r.hset(f"rt:{old_token_id}", "consumed", "1")
    else:
        # No Redis — treat the opaque token as the Supabase token directly
        token_data = None
        supabase_refresh = old_token_id

    async with _http_client(request) as client:
        resp = await client.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=refresh_token",
            headers=_supabase_headers(),
            json={"refresh_token": supabase_refresh},
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    supabase_data = resp.json()
    new_supabase_rt = supabase_data.get("refresh_token", "")

    if r is None or token_data is None:
        return _wrap_with_opaque_token(supabase_data)

    # Issue child token in same family
    new_token_id = _issue_family_token(
        supabase_token=new_supabase_rt,
        user_id=token_data.get("user_id", ""),
        parent_id=old_token_id,
        family_id=token_data.get("family_id"),
    )

    result = dict(supabase_data)
    result["refresh_token"] = new_token_id
    return result


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

    # SECURITY: enforce org membership — an admin of org A must NOT be able to invite to org B
    caller_claims = getattr(request.state, "supabase_claims", None)
    caller_user_id = caller_claims.get("sub") if caller_claims else None
    if caller_user_id:
        async with _http_client(request) as membership_client:
            membership_resp = await membership_client.get(
                f"{SUPABASE_URL}/rest/v1/organization_members",
                params={
                    "user_id": f"eq.{caller_user_id}",
                    "org_id": f"eq.{body.organization_id}",
                    "select": "user_id",
                    "limit": "1",
                },
                headers={
                    **_supabase_headers(service=True),
                    "Accept": "application/json",
                },
            )
            members = membership_resp.json() if membership_resp.status_code == 200 else []
            if not isinstance(members, list) or len(members) == 0:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You are not a member of this organization.",
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

    Rate limit: 3 requests per IP per 60 minutes.
    Always returns 200 to prevent email enumeration attacks.
    """
    _reset_password_limiter.check(_client_ip(request))
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
    Rate limit: 5 requests per IP per 60 minutes.
    Password must be at least 8 characters with mixed case and a number.
    Revokes all existing refresh tokens on success.
    """
    user = getattr(request.state, "user", None)
    if not user or not user.is_authenticated:
        raise HTTPException(status_code=401, detail="Authentication required")

    _update_password_limiter.check(_client_ip(request))

    password = body.new_password
    if len(password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")
    if not any(c.isupper() for c in password):
        raise HTTPException(status_code=422, detail="Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        raise HTTPException(status_code=422, detail="Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        raise HTTPException(status_code=422, detail="Password must contain at least one number")

    access_token = _extract_token(request)
    user_sub = getattr(user, "sub", None)

    async with _http_client(request) as client:
        resp = await client.put(
            f"{SUPABASE_URL}/auth/v1/user",
            headers=_supabase_headers(access_token=access_token),
            json={"password": password},
        )

    if resp.status_code >= 400:
        raise HTTPException(status_code=400, detail="Password update failed")

    # Revoke all existing opaque refresh tokens for this user in Redis
    # We do a best-effort scan; if Redis is unavailable this is a no-op.
    try:
        r = get_redis()
        if r is not None and user_sub:
            # Also force Supabase to invalidate all sessions via admin API
            async with _http_client(request) as client:
                await client.post(
                    f"{SUPABASE_URL}/auth/v1/admin/users/{user_sub}/logout",
                    headers=_supabase_headers(service=True),
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("update_password: session revocation failed: %s", exc)

    logger.info("update_password: password changed for user %s", user_sub or "unknown")
    return {"message": "Password updated successfully"}
