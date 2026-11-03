"""HTTP hardening: request-size limit, HTTPS requirement, security headers, and error responses that leak nothing.

Pure ASGI middlewares (no body buffering beyond counting) plus two exception handlers:

* validation errors return only the field location, a short message and the error type: never the submitted value, so a
  mistyped password or a large payload is not echoed back;
* any unexpected exception returns a generic 500 with a request id. The stack trace is logged on the server only, never sent.
"""
import ipaddress
import json
import logging
import uuid

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.config import get_settings

logger = logging.getLogger("insider_threat.security")
DOC_PATHS = ("/docs", "/redoc", "/openapi.json")
HEALTH_PATH = "/api/health"


class _TooLarge(BaseException):
    """BaseException on purpose: FastAPI turns ordinary exceptions raised while reading a body into a 400."""


async def _reject(send, status_code: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status_code,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def _effective_scheme(scope) -> str:
    """The request scheme. X-Forwarded-Proto counts only when TRUST_FORWARDED_PROTO is set (a proxy you control sets it)."""
    scheme = scope.get("scheme", "http")
    if get_settings().trust_forwarded_proto:
        for key, value in scope.get("headers", []):
            if key == b"x-forwarded-proto":
                return value.decode("latin-1").split(",")[0].strip().lower()
    return scheme


def _is_loopback(scope) -> bool:
    client = scope.get("client")
    try:
        return bool(client) and ipaddress.ip_address(client[0]).is_loopback
    except ValueError:
        return False


class RequestSizeLimitMiddleware:
    """Reject bodies larger than MAX_REQUEST_BYTES (declared or streamed) with 413 before they are parsed."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = get_settings().max_request_bytes
        for key, value in scope["headers"]:
            if key == b"content-length" and value.isdigit() and int(value) > limit:
                return await _reject(send, 413, "Request body too large")
        received, started = 0, False

        async def tracking_send(message):
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _TooLarge()
            return message

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            if started:
                raise
            await _reject(send, 413, "Request body too large")


class HttpsRequiredMiddleware:
    """With REQUIRE_HTTPS, refuse plain-HTTP requests (loopback and the health check are exempt, see README)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and get_settings().require_https and scope["path"] != HEALTH_PATH \
                and _effective_scheme(scope) != "https" and not _is_loopback(scope):
            return await _reject(send, 400, "HTTPS is required")
        await self.app(scope, receive, send)


class SecurityHeadersMiddleware:
    """Defensive response headers. The API serves JSON only, so a strict CSP is safe (not applied to the docs pages)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        https = _effective_scheme(scope) == "https"
        is_docs = scope["path"] in DOC_PATHS

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                extra = {b"x-content-type-options": b"nosniff", b"x-frame-options": b"DENY", b"referrer-policy": b"no-referrer",
                         b"cross-origin-resource-policy": b"same-site", b"permissions-policy": b"geolocation=(), camera=(), microphone=()"}
                if not is_docs:
                    extra[b"cache-control"] = b"no-store"
                    extra[b"content-security-policy"] = b"default-src 'none'; frame-ancestors 'none'"
                if https:
                    extra[b"strict-transport-security"] = b"max-age=31536000; includeSubDomains"
                headers += [(k, v) for k, v in extra.items() if k not in present]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


def install_error_handlers(app) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError):
        errors = [{"loc": [str(part) for part in e.get("loc", ())], "msg": str(e.get("msg", "Invalid value"))[:200],
                   "type": str(e.get("type", "invalid"))} for e in exc.errors()[:20]]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        request_id = uuid.uuid4().hex[:12]
        logger.error("Unhandled error %s on %s %s", request_id, request.method, request.url.path,
                     exc_info=(type(exc), exc, exc.__traceback__))
        return JSONResponse(status_code=500, content={"detail": "Internal server error", "request_id": request_id})
