"""
Security headers middleware for signal-studio-auth.

Adds HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, and Permissions-Policy to every response.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Inject security headers on every outgoing response.

    Headers applied:
    - Strict-Transport-Security (HSTS) — force HTTPS for 1 year
    - Content-Security-Policy — restrict resource loading
    - X-Frame-Options — prevent clickjacking
    - X-Content-Type-Options — prevent MIME sniffing
    - Referrer-Policy — limit referrer leakage
    - Permissions-Policy — disable unneeded browser APIs
    - X-XSS-Protection — legacy XSS filter (belt + suspenders)
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), interest-cohort=()"
        )
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response
