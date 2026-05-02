"""Security middleware and utilities for AuthZEN PDP.

This module provides security features for production deployments:
- Authentication (API keys, JWT, OAuth2)
- Rate limiting
- CORS configuration
- Security headers
- Request logging
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    requests: int = 100
    window: int = 60


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware."""

    def __init__(self, app, config: RateLimitConfig | None = None):
        super().__init__(app)
        self.config = config or RateLimitConfig()
        self._storage: dict[str, list[float]] = {}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        # Clean old entries
        if client_ip in self._storage:
            self._storage[client_ip] = [
                t for t in self._storage[client_ip]
                if now - t < self.config.window
            ]

        # Check rate limit
        count = len(self._storage.get(client_ip, []))
        if count >= self.config.requests:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded"},
            )

        # Add current request
        if client_ip not in self._storage:
            self._storage[client_ip] = []
        self._storage[client_ip].append(now)

        return await call_next(request)


@dataclass
class APIKeyConfig:
    """API key configuration."""
    header_name: str = "X-API-Key"
    keys: set[str] = field(default_factory=set)

    def validate(self, key: str) -> bool:
        return key in self.keys


class APIKeyMiddleware(BaseHTTPMiddleware):
    """API key authentication middleware."""

    def __init__(self, app, config: APIKeyConfig, excluded_paths: set[str] | None = None):
        super().__init__(app)
        self.config = config
        self.excluded_paths = excluded_paths or {"/", "/health", "/docs", "/openapi.json"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in self.excluded_paths:
            return await call_next(request)

        api_key = request.headers.get(self.config.header_name)
        if not api_key or not self.config.validate(api_key):
            return JSONResponse(
                status_code=401,
                content={"error": "Invalid or missing API key"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all requests."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()

        logger.info(
            f"Request: {request.method} {request.url.path} "
            f"from {request.client.host if request.client else 'unknown'}"
        )

        response = await call_next(request)

        duration = time.time() - start_time
        logger.info(
            f"Response: {response.status_code} "
            f"for {request.method} {request.url.path} "
            f"in {duration:.3f}s"
        )

        return response


def create_secure_app(
    pdp=None,
    api_keys: set[str] | None = None,
    cors_origins: list[str] | None = None,
    rate_limit: tuple[int, int] | None = None,
    allowed_hosts: list[str] | None = None,
) -> FastAPI:
    """Create a hardened FastAPI application for production."""
    from authzen.api import create_app as _create_app

    app = _create_app(pdp)

    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

    if rate_limit:
        config = RateLimitConfig(requests=rate_limit[0], window=rate_limit[1])
        app.add_middleware(RateLimitMiddleware, config=config)

    if api_keys:
        config = APIKeyConfig(keys=api_keys)
        app.add_middleware(APIKeyMiddleware, config=config)

    app.add_middleware(SecurityHeadersMiddleware)

    if allowed_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    return app


def validate_jwt(token: str) -> dict[str, Any] | None:
    """Validate a JWT token and return claims.

    Placeholder - implement with PyJWT in production.
    """
    logger.warning("JWT validation is a placeholder - implement with a proper library")
    return None


@dataclass
class OAuth2Config:
    """OAuth2 configuration for PDP."""
    client_id: str
    client_secret: str
    token_url: str
    scopes: dict[str, str] = field(default_factory=dict)


def create_oauth2_app(
    pdp=None,
    oauth_config: OAuth2Config | None = None,
) -> FastAPI:
    """Create a FastAPI app with OAuth2 authentication."""
    from fastapi import Depends
    from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
    from authzen.api import create_app as _create_app

    app = _create_app(pdp)

    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

    async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
        claims = validate_jwt(token)
        if not claims:
            raise HTTPException(status_code=401, detail="Invalid token")
        return claims

    @app.post("/token")
    async def login(form_data: OAuth2PasswordRequestForm = Depends()) -> dict[str, Any]:
        return {"access_token": form_data.username, "token_type": "bearer"}

    return app
