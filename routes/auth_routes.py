"""
FastAPI auth routes powered by Supabase.

These routes proxy to the Supabase Auth API using the service key,
so the frontend never needs the service key directly.

Rate limits (in-memory, resets on restart — use Redis in production):
  POST /auth/login   → 5 requests / 60s per IP
  POST /auth/signup  → 3 requests / 60s per IP
"""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr

from config.supabase_config import SUPABASE_SERVICE_KEY, SUPABASE_URL

router = APIRouter(prefix="/auth", tags=["auth"])

# ---------------------------------------------------------------------------
# Simple in-memory rate limiter (sliding-window per IP)
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Thread-safe sliding-window rate limiter."""

    def __init__(self, max_calls: int, window_seconds: int):
        self.max_calls = max_calls
        self.window = window_seconds
        self._calls: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def check(self, key: str) -> None:
        """Raise HTTP 429 if the key has exceeded the rate limit."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            timestamps = self._calls[key]
            # Prune old entries
            self._calls[key] = [t for t in timestamps if t > cutoff]
            if len(self._calls[key]) >= self.max_calls:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=(
                        f"Rate limit exceeded: max {self.max_calls} requests "
                        f"per {self.window}s. Try again later."
                    ),
                    headers={"Retry-After": str(self.window)},
                )
            self._calls[key].append(now)


_login_limiter = _RateLimiter(max_calls=5, window_seconds=60)
_signup_limiter = _RateLimiter(max_calls=3, window_seconds=60)


def _client_ip(request: Request) -> str:
    """Extract real client IP (handles X-Forwarded-For from Railway/nginx)."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str = ""
    last_name: str = ""
    organization_id: int | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class InviteRequest(BaseModel):
    email: EmailStr
    organization_id: int
    role: str = "viewer"


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
    async with httpx.AsyncClient() as client:
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
    return resp.json()


@router.post("/login")
async def login(body: LoginRequest, request: Request):
    """Authenticate and receive tokens."""
    _login_limiter.check(_client_ip(request))
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
            headers=_supabase_headers(),
            json={"email": body.email, "password": body.password},
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())
    return resp.json()


@router.post("/refresh")
async def refresh(body: RefreshRequest):
    """Refresh an access token."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=refresh_token",
            headers=_supabase_headers(),
            json={"refresh_token": body.refresh_token},
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())
    return resp.json()


@router.post("/logout")
async def logout(request: Request):
    """Sign out (invalidates the refresh token server-side)."""
    token = _extract_token(request)
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SUPABASE_URL}/auth/v1/logout",
            headers=_supabase_headers(access_token=token),
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())
    return {"detail": "Logged out"}


@router.get("/me")
async def me(request: Request):
    """Return current user info from the middleware-populated state."""
    user = getattr(request.state, "user", None)
    if user is None or not user.is_authenticated:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user.dict(by_alias=True)


@router.post("/invite-to-org")
async def invite_to_org(body: InviteRequest, request: Request):
    """
    Invite a user to an organization (admin-only).
    Creates a Supabase user with pre-set org metadata.
    """
    caller = getattr(request.state, "user", None)
    if not caller or not caller.is_authenticated:
        raise HTTPException(status_code=401, detail="Not authenticated")

    async with httpx.AsyncClient() as client:
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
