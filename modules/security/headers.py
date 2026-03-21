"""
Aegis Security Platform — Security Headers Middleware
=====================================================
FedRAMP High / IL6: NIST 800-53 Rev5 SC-8, SC-28, SI-10

Applies the full defensive HTTP header set to every response:
  - HSTS           : force HTTPS, prevent downgrade attacks
  - CSP            : block XSS, clickjacking, injection
  - X-Frame-Options: prevent iframe embedding
  - X-Content-Type : prevent MIME sniffing
  - Referrer-Policy: prevent sensitive URL leakage
  - Permissions-Policy: lock down browser APIs

Also enforces:
  - Request ID propagation (correlation_id for AU-3)
  - Server header scrubbing (prevent fingerprinting)
  - Large request body rejection (DoS / injection prevention)
"""

from __future__ import annotations

import time
import uuid

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

MAX_REQUEST_BODY_BYTES: int = 1 * 1024 * 1024  # 1 MB hard limit


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Apply security headers and request hygiene to every request/response.

    Add to FastAPI app:
        from modules.security.headers import SecurityHeadersMiddleware
        app.add_middleware(SecurityHeadersMiddleware)
    """

    def __init__(self, app: ASGIApp, csp_report_uri: str = "") -> None:
        super().__init__(app)
        self.csp_report_uri = csp_report_uri

    async def dispatch(self, request: Request, call_next) -> Response:
        # ── Reject oversized bodies before routing ─────────────────────────
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_BODY_BYTES:
            return Response(
                content='{"detail":"Request body too large"}',
                status_code=413,
                media_type="application/json",
            )

        # ── Correlation ID ────────────────────────────────────────────────
        correlation_id = (
            request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )
        request.state.correlation_id = correlation_id
        request.state.start_time = time.monotonic()

        response: Response = await call_next(request)

        # ── HSTS (HTTP Strict Transport Security) ─────────────────────────
        # max-age=63072000 = 2 years; includeSubDomains; preload
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )

        # ── Content Security Policy ────────────────────────────────────────
        # Dashboard uses React CDN + Recharts CDN — allowed in script-src
        csp_parts = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com",
            "img-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "object-src 'none'",
        ]
        if self.csp_report_uri:
            csp_parts.append(f"report-uri {self.csp_report_uri}")
        response.headers["Content-Security-Policy"] = "; ".join(csp_parts)

        # ── Anti-clickjacking ──────────────────────────────────────────────
        response.headers["X-Frame-Options"] = "DENY"

        # ── MIME sniffing prevention ───────────────────────────────────────
        response.headers["X-Content-Type-Options"] = "nosniff"

        # ── Referrer policy ───────────────────────────────────────────────
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # ── Permissions policy (lock down browser features) ───────────────
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), bluetooth=()"
        )

        # ── Cross-Origin policies ──────────────────────────────────────────
        response.headers["Cross-Origin-Opener-Policy"]   = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

        # ── Cache control for API responses ───────────────────────────────
        if request.url.path.startswith("/api/") or request.url.path.startswith("/admin/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"

        # ── Scrub server fingerprint ───────────────────────────────────────
        response.headers["Server"] = "Aegis"
        response.headers.pop("X-Powered-By", None)

        # ── Correlation ID passthrough ─────────────────────────────────────
        response.headers["X-Correlation-ID"] = correlation_id

        # ── Timing header (for performance monitoring) ─────────────────────
        elapsed_ms = int((time.monotonic() - request.state.start_time) * 1000)
        response.headers["X-Response-Time"] = f"{elapsed_ms}ms"

        return response


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    SI-10 Input Validation:
    - Block requests with null bytes (injection precursor)
    - Block excessively long headers
    - Block requests with invalid Content-Type for mutation endpoints
    """

    _MAX_HEADER_VALUE_LEN = 8192
    _MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    async def dispatch(self, request: Request, call_next) -> Response:
        # Null byte injection check in URL
        if "\x00" in str(request.url):
            return Response(
                content='{"detail":"Invalid request"}',
                status_code=400,
                media_type="application/json",
            )

        # Oversized header check
        for header_name, header_value in request.headers.items():
            if len(header_value) > self._MAX_HEADER_VALUE_LEN:
                return Response(
                    content='{"detail":"Header too large"}',
                    status_code=431,
                    media_type="application/json",
                )

        # Content-Type enforcement on mutation endpoints
        if (
            request.method in self._MUTATION_METHODS
            and request.url.path.startswith(("/api/", "/admin/", "/secure", "/revoke"))
            and "content-type" in request.headers
            and "application/json" not in request.headers["content-type"]
            and "multipart" not in request.headers["content-type"]
        ):
            return Response(
                content='{"detail":"Content-Type must be application/json"}',
                status_code=415,
                media_type="application/json",
            )

        return await call_next(request)
