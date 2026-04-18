"""App-level security-header middleware — defence in depth vs. Nginx.

Nginx already adds these headers in front of us (see nginx/nginx.conf),
but in dev (no Nginx) and behind any unusual proxy topology the app must
still set them. We set a narrow set here and SKIP anything Nginx would
better handle (e.g. HSTS is only emitted when the request is clearly HTTPS).
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Matches nginx/nginx.conf — don't diverge without updating both.
_STATIC_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    # Legacy header; modern browsers rely on CSP but Nginx still sets it.
    "X-XSS-Protection": "1; mode=block",
}

_HSTS_VALUE = "max-age=63072000; includeSubDomains; preload"

# API-only CSP — no HTML served, so block everything except same-origin JSON.
# Frontend HTML is served by Next.js behind Nginx, which adds a more permissive
# CSP for that flow.
_API_CSP = "default-src 'none'; frame-ancestors 'none'"


def _is_secure(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    return "https" in forwarded_proto.lower()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        for header, value in _STATIC_HEADERS.items():
            response.headers.setdefault(header, value)

        # Only emit HSTS over HTTPS — never over plain HTTP (spec).
        if _is_secure(request):
            response.headers.setdefault("Strict-Transport-Security", _HSTS_VALUE)

        # All our API responses are JSON. Set a locked-down CSP; Nginx will
        # override for HTML (frontend) routes.
        if "application/json" in response.headers.get("content-type", ""):
            response.headers.setdefault("Content-Security-Policy", _API_CSP)

        return response
