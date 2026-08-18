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

    Only ``app_metadata.role`` is trusted — it is set server-side via the
    Supabase service key and cannot be forged by the end user.

    ``user_metadata.role`` is intentionally NOT consulted: Supabase end
    users can edit their own ``user_metadata`` (e.g. via the client-side
    ``updateUser`` API), so honoring it here would let anyone self-assign
    a privileged role such as ``admin`` or ``org_manager``. See the
    privilege-escalation fix in TASK S7.

    Returns an empty string if the request is unauthenticated, claims are
    absent, or no role is set in ``app_metadata``.
    """
    claims = getattr(request.state, "supabase_claims", None)
    if claims is None:
        return ""
    # app_metadata is set by the service key — this is the ONLY authoritative
    # field. Do not fall back to user_metadata.role (user-editable, forgeable).
    role = claims.get("app_metadata", {}).get("role", "")
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
