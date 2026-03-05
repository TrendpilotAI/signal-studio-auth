"""
RBAC — require_role() FastAPI dependency (TODO-356).

Usage:
    from middleware.rbac import require_role

    @router.post("/admin/endpoint")
    async def admin_only(request: Request, _: None = Depends(require_role("admin"))):
        ...

    @router.post("/org-manager")
    async def multi_role(request: Request, _: None = Depends(require_role("admin", "org_manager"))):
        ...

The dependency reads the caller's role from ``request.state.supabase_claims``
(populated by SupabaseAuthMiddleware) and raises HTTP 401 / 403 as appropriate.
"""

from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException, Request, status


def _get_caller_role(request: Request) -> str:
    """
    Extract the caller's role from Supabase JWT claims.

    Priority order (highest wins):
    1. ``app_metadata.role`` — set server-side via service key, cannot be forged by users
    2. ``user_metadata.role`` — fallback (user-editable, lower trust)

    Returns an empty string if the request is unauthenticated or claims are absent.
    """
    claims = getattr(request.state, "supabase_claims", None)
    if claims is None:
        return ""
    # app_metadata is set by the service key — this is the authoritative field
    role = claims.get("app_metadata", {}).get("role", "")
    if not role:
        # Graceful fallback to user_metadata (lower trust)
        role = claims.get("user_metadata", {}).get("role", "")
    return role or ""


def require_role(*allowed_roles: str) -> Callable:
    """
    Return a FastAPI dependency that enforces the caller has one of *allowed_roles*.

    Raises:
        HTTP 401 — no authenticated user on the request state
        HTTP 403 — user is authenticated but does not have the required role

    Example::

        @router.delete("/users/{user_id}")
        async def delete_user(
            user_id: str,
            request: Request,
            _: None = Depends(require_role("admin", "super_admin")),
        ):
            ...
    """
    if not allowed_roles:
        raise ValueError("require_role() requires at least one role argument")

    allowed_set = frozenset(r.strip().lower() for r in allowed_roles)

    async def _dependency(request: Request) -> None:
        # Confirm the user is authenticated
        user = getattr(request.state, "user", None)
        if user is None or not getattr(user, "is_authenticated", False):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        caller_role = _get_caller_role(request).lower()
        if caller_role not in allowed_set:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient permissions. Required role: "
                    f"{' or '.join(sorted(allowed_set))}. "
                    f"Current role: {caller_role!r}"
                ),
            )

    return Depends(_dependency)
