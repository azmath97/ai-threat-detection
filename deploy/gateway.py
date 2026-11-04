"""Public entry point of the single-container deployment.

The container runs four processes: the FastAPI backend and three Streamlit apps, all on 127.0.0.1. Only this gateway listens
on the public port. It routes by path, keeps the backend API private, gates the administrator apps, and proxies the websocket
that Streamlit needs.

    /            Employee Workspace Portal
    /soc/        SOC Dashboard            (administrator gate, then the application's own administrator sign-in)
    /console/    Simulation Console       (administrator gate, then the application's own administrator sign-in)
    /healthz     liveness and readiness of all four processes (only ok / down per component)
    /api/...     not routed: the backend is never reachable from the internet

Why the API stays private: every request the backend sees from this container comes from loopback, which the backend maps to
the signed-in employee's registered workstation address (MAP_LOOPBACK_TO_WORKSTATION). If the API were proxied, an attacker
using it would inherit that attribution and the unfamiliar-address signals would stop working.

The administrator gate is HTTP Basic authentication in front of the SOC and console apps (ADMIN_UI_USER / ADMIN_UI_PASSWORD), in
addition to the application's own sign-in and role checks. After a successful Basic login the gateway sets a signed, HttpOnly,
SameSite=Strict cookie so websocket connections, which some browsers send without Basic credentials, are admitted too.

Run:  uvicorn deploy.gateway:create_app --factory --host 0.0.0.0 --port $PORT
"""
import asyncio
import base64
import hashlib
import hmac
import logging
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

log = logging.getLogger("gateway")

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"}
SERVER_OWNED = {"date", "server"}                     # uvicorn adds its own
GATE_COOKIE = "itd_admin_gate"
GATE_COOKIE_SECONDS = 8 * 3600
QUIET_SUFFIXES = ("/healthz", "/_stcore/health")


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class GatewayConfig:
    backend: str = "127.0.0.1:8000"
    portal: str = "127.0.0.1:8501"
    console: str = "127.0.0.1:8502"
    soc: str = "127.0.0.1:8503"
    admin_user: str = ""
    admin_password: str = ""
    allow_open_admin: bool = False
    gate_key: bytes = b""
    force_https: bool = False
    max_gate_failures: int = 10
    gate_window_seconds: int = 300
    health_timeout: float = 2.0
    failures: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls, env=None) -> "GatewayConfig":
        env = os.environ if env is None else env
        secret = env.get("SECRET_KEY", "")
        return cls(
            backend=f"127.0.0.1:{env.get('API_PORT', '8000')}", portal=f"127.0.0.1:{env.get('PORTAL_PORT', '8501')}",
            console=f"127.0.0.1:{env.get('CONSOLE_PORT', '8502')}", soc=f"127.0.0.1:{env.get('SOC_PORT', '8503')}",
            admin_user=env.get("ADMIN_UI_USER", ""), admin_password=env.get("ADMIN_UI_PASSWORD", ""),
            allow_open_admin=_flag(env.get("ALLOW_OPEN_ADMIN_UI")),
            gate_key=hmac.new(secret.encode(), b"westbridge-admin-gate-cookie", hashlib.sha256).digest(),
            force_https=_flag(env.get("FORCE_HTTPS")),
        )


# ------------------------------------------------------------------------------------------------------------- routing
def route_for(path: str, cfg: GatewayConfig) -> tuple[str, str, bool]:
    """(upstream name, upstream host:port, needs the administrator gate)."""
    for prefix, name, target in (("/soc", "soc", cfg.soc), ("/console", "console", cfg.console)):
        if path == prefix or path.startswith(prefix + "/"):
            return name, target, True
    return "portal", cfg.portal, False


# ---------------------------------------------------------------------------------------------------- administrator gate
def _sign(cfg: GatewayConfig, issued: int) -> str:
    mac = hmac.new(cfg.gate_key, str(issued).encode(), hashlib.sha256).hexdigest()
    return f"{issued}.{mac}"


def _cookie_valid(cfg: GatewayConfig, value: str | None) -> bool:
    if not value or "." not in value:
        return False
    issued, _, _mac = value.partition(".")
    if not issued.isdigit() or time.time() - int(issued) > GATE_COOKIE_SECONDS or int(issued) > time.time() + 60:
        return False
    return hmac.compare_digest(_sign(cfg, int(issued)), value)


def _basic_valid(cfg: GatewayConfig, header: str | None) -> bool:
    if not header or not header.lower().startswith("basic ") or not cfg.admin_user or not cfg.admin_password:
        return False
    try:
        user, _, password = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8").partition(":")
    except (ValueError, UnicodeDecodeError):
        return False
    ok_user = hmac.compare_digest(user.encode(), cfg.admin_user.encode())
    ok_pass = hmac.compare_digest(password.encode(), cfg.admin_password.encode())
    return ok_user and ok_pass


def _client_key(headers, peer: str) -> str:
    forwarded = headers.get("x-forwarded-for", "")
    return forwarded.split(",")[-1].strip() if forwarded else peer       # the address the platform's proxy saw


def _throttled(cfg: GatewayConfig, key: str) -> bool:
    now = time.time()
    recent = [t for t in cfg.failures.get(key, []) if now - t < cfg.gate_window_seconds]
    cfg.failures[key] = recent
    return len(recent) >= cfg.max_gate_failures


def _record_failure(cfg: GatewayConfig, key: str) -> None:
    cfg.failures.setdefault(key, []).append(time.time())
    if len(cfg.failures) > 5000:                                          # bounded memory under a flood of distinct addresses
        cfg.failures.pop(next(iter(cfg.failures)))


def gate_decision(cfg: GatewayConfig, headers, cookies: dict, peer: str) -> tuple[str, bool]:
    """('ok' | 'denied' | 'throttled', whether to set a fresh gate cookie)."""
    if cfg.allow_open_admin:
        return "ok", False
    if _cookie_valid(cfg, cookies.get(GATE_COOKIE)):
        return "ok", False
    key = _client_key(headers, peer)
    if _throttled(cfg, key):
        return "throttled", False
    if _basic_valid(cfg, headers.get("authorization")):
        return "ok", True
    if headers.get("authorization"):
        _record_failure(cfg, key)                                         # only wrong credentials count, not the first empty challenge
    return "denied", False


def _is_https(headers, scheme: str) -> bool:
    return headers.get("x-forwarded-proto", scheme).split(",")[0].strip().lower() in ("https", "wss")


def _without_gate_cookie(cookie: str | None) -> str:
    parts = [p for p in (c.strip() for c in (cookie or "").split(";")) if p and not p.startswith(GATE_COOKIE + "=")]
    return "; ".join(parts)


def _forward_headers(request: Request, peer: str) -> dict:
    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
    cookie = _without_gate_cookie(headers.get("cookie"))
    headers.pop("cookie", None)
    if cookie:
        headers["cookie"] = cookie
    chain = request.headers.get("x-forwarded-for")
    headers["x-forwarded-for"] = f"{chain}, {peer}" if chain else peer
    headers["x-forwarded-proto"] = request.headers.get("x-forwarded-proto", request.url.scheme)
    headers["x-forwarded-host"] = request.headers.get("host", "")
    return headers


# ------------------------------------------------------------------------------------------------------------- app
def create_app(cfg: GatewayConfig | None = None) -> Starlette:
    cfg = cfg or GatewayConfig.from_env()
    client = httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=5.0),
                               limits=httpx.Limits(max_connections=200, max_keepalive_connections=40))

    def secure(response: Response, request: Request) -> Response:
        response.headers.setdefault("x-content-type-options", "nosniff")
        response.headers.setdefault("referrer-policy", "same-origin")
        response.headers.setdefault("x-frame-options", "SAMEORIGIN")
        if _is_https(request.headers, request.url.scheme):
            response.headers.setdefault("strict-transport-security", "max-age=31536000")
        return response

    async def probe(name: str, url: str) -> tuple[str, bool]:
        try:
            r = await client.get(url, timeout=cfg.health_timeout)
            return name, r.status_code == 200
        except httpx.HTTPError:
            return name, False

    async def healthz(request: Request) -> Response:
        results = await asyncio.gather(
            probe("backend", f"http://{cfg.backend}/api/health"), probe("portal", f"http://{cfg.portal}/_stcore/health"),
            probe("console", f"http://{cfg.console}/console/_stcore/health"), probe("soc", f"http://{cfg.soc}/soc/_stcore/health"))
        healthy = all(ok for _, ok in results)
        return JSONResponse({"status": "ok" if healthy else "unavailable", "components": {n: "ok" if ok else "down" for n, ok in results}},
                            status_code=200 if healthy else 503, headers={"cache-control": "no-store"})

    async def not_found(request: Request) -> Response:
        return secure(JSONResponse({"detail": "Not found"}, status_code=404), request)

    async def proxy(request: Request) -> Response:
        started = time.perf_counter()
        path = request.url.path
        peer = request.client.host if request.client else "unknown"
        if cfg.force_https and not _is_https(request.headers, request.url.scheme):
            query = f"?{request.url.query}" if request.url.query else ""
            return RedirectResponse(f"https://{request.headers.get('host', '')}{path}{query}", status_code=308)
        name, target, gated = route_for(path, cfg)
        set_cookie = False
        if gated:
            decision, set_cookie = gate_decision(cfg, request.headers, request.cookies, peer)
            if decision == "throttled":
                log.warning("admin gate throttled for %s", _client_key(request.headers, peer))
                return secure(PlainTextResponse("Too many failed attempts. Try again later.", status_code=429,
                                                headers={"retry-after": str(cfg.gate_window_seconds)}), request)
            if decision != "ok":
                if request.headers.get("authorization"):
                    log.warning("admin gate refused credentials for %s from %s", name, _client_key(request.headers, peer))
                return secure(PlainTextResponse("Authentication required.", status_code=401,
                                                headers={"www-authenticate": 'Basic realm="Westbridge administrators", charset="UTF-8"'}), request)
        url = f"http://{target}{path}" + (f"?{request.url.query}" if request.url.query else "")
        try:
            upstream = await client.send(client.build_request(request.method, url, headers=_forward_headers(request, peer),
                                                              content=request.stream()), stream=True)
        except httpx.HTTPError as exc:
            log.error("upstream %s unavailable: %s", name, type(exc).__name__)
            return secure(PlainTextResponse("The service is temporarily unavailable.", status_code=502), request)
        response = StreamingResponse(upstream.aiter_raw(), status_code=upstream.status_code,
                                     headers={k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP | SERVER_OWNED},
                                     background=BackgroundTask(upstream.aclose))
        if set_cookie:
            response.set_cookie(GATE_COOKIE, _sign(cfg, int(time.time())), max_age=GATE_COOKIE_SECONDS, httponly=True,
                                samesite="strict", secure=_is_https(request.headers, request.url.scheme), path="/")
        secure(response, request)
        if not path.endswith(QUIET_SUFFIXES):
            log.info("%s %s -> %s %s (%.0f ms)", request.method, path, name, upstream.status_code, (time.perf_counter() - started) * 1000)
        return response

    async def ws_proxy(websocket: WebSocket) -> None:
        path = websocket.url.path
        peer = websocket.client.host if websocket.client else "unknown"
        name, target, gated = route_for(path, cfg)
        if gated:
            decision, _ = gate_decision(cfg, websocket.headers, websocket.cookies, peer)
            if decision != "ok":
                log.warning("admin gate %s for a websocket to %s", decision, name)
                await websocket.close(code=4401)
                return
        query = f"?{websocket.url.query}" if websocket.url.query else ""
        extra = {k: websocket.headers[k] for k in ("user-agent",) if k in websocket.headers}
        cookie = _without_gate_cookie(websocket.headers.get("cookie"))
        if cookie:
            extra["cookie"] = cookie
        wanted = list(websocket.scope.get("subprotocols") or [])
        try:
            upstream = await ws_connect(f"ws://{target}{path}{query}", subprotocols=wanted or None, additional_headers=extra,
                                                origin=websocket.headers.get("origin"), max_size=None, open_timeout=10, ping_interval=None)
        except Exception as exc:  # noqa: BLE001 - any failure to reach the upstream is reported as a refused socket
            log.error("websocket upstream %s unavailable: %s", name, type(exc).__name__)
            await websocket.close(code=1013)
            return
        await websocket.accept(subprotocol=upstream.subprotocol)

        async def client_to_upstream() -> None:
            try:
                while True:
                    message = await websocket.receive()
                    if message["type"] == "websocket.disconnect":
                        break
                    if message.get("bytes") is not None:
                        await upstream.send(message["bytes"])
                    elif message.get("text") is not None:
                        await upstream.send(message["text"])
            except (WebSocketDisconnect, ConnectionClosed, RuntimeError):
                pass

        async def upstream_to_client() -> None:
            try:
                async for message in upstream:
                    if isinstance(message, bytes):
                        await websocket.send_bytes(message)
                    else:
                        await websocket.send_text(message)
            except (WebSocketDisconnect, ConnectionClosed, RuntimeError):
                pass

        tasks = [asyncio.create_task(client_to_upstream()), asyncio.create_task(upstream_to_client())]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await upstream.close()
            try:
                await websocket.close()
            except RuntimeError:
                pass

    @asynccontextmanager
    async def lifespan(_app):
        yield
        await client.aclose()

    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    return Starlette(routes=[
        Route("/healthz", healthz, methods=["GET", "HEAD"]),
        Route("/api", not_found, methods=methods), Route("/api/{rest:path}", not_found, methods=methods),
        Route("/docs", not_found, methods=methods), Route("/redoc", not_found, methods=methods),
        Route("/openapi.json", not_found, methods=methods),
        WebSocketRoute("/{path:path}", ws_proxy),
        Route("/{path:path}", proxy, methods=methods),
    ], lifespan=lifespan)


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)      # one line per health probe is noise
