"""Authentification par jeton, limitation de débit, en-têtes de sécurité."""
import hmac
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from . import config

HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self'; "
                                "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
                                "frame-ancestors 'none'; form-action 'self'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
}
_hits: dict[str, deque] = defaultdict(deque)
_lock = threading.Lock()


def client_ip(request: Request) -> str:
    parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    if config.PROXY_HOPS and len(parts) >= config.PROXY_HOPS:
        return parts[-config.PROXY_HOPS]
    return request.client.host if request.client else "unknown"


def _check(key: str, limit: int, window: int = 60) -> None:
    now = time.monotonic()
    with _lock:
        q = _hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            raise HTTPException(429, "Too many requests", headers={"Retry-After": str(window)})
        q.append(now)
        if len(_hits) > 5000:
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > window]:
                del _hits[k]


def rate_limit(request: Request) -> None:
    _check("g:" + client_ip(request), config.RATE_PER_MIN)


def heavy_limit(request: Request) -> None:
    _check("h:" + client_ip(request), config.HEAVY_PER_MIN)


def has_valid_token(request: Request) -> bool:
    if not config.API_TOKEN:
        return False
    h = request.headers.get("authorization", "")
    supplied = h[7:] if h[:7].lower() == "bearer " else ""
    return hmac.compare_digest(supplied.encode(), config.API_TOKEN.encode())


def require_token(request: Request) -> None:
    if not config.API_TOKEN:
        raise HTTPException(503, "API token not configured on the server")
    if not has_valid_token(request):
        _check("f:" + client_ip(request), 8)  # 8 échecs/min max, puis 429
        raise HTTPException(401, "Invalid or missing token", headers={"WWW-Authenticate": "Bearer"})
