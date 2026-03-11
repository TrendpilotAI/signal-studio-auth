"""
Security headers middleware for signal-studio-auth.

Adds HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, and Permissions-Policy to every response.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": (
        "default-src 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "X-XSS-Protection": "1; mode=block",
}


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
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response
