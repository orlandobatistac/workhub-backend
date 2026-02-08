"""FastAPI application factory and app configuration for WorkHub.

This module creates the FastAPI `app`, configures middleware (CORS, rate limiting),
registers routers under `app.routers.*` when available and initializes the DB
on startup (calls `app.database.init_db`).
"""

from __future__ import annotations

import importlib
import logging
import os
from typing import List

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.database import init_db

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))


DEFAULT_RATE_LIMIT = os.getenv("RATE_LIMIT", "10/minute")
limiter = Limiter(key_func=get_remote_address, default_limits=[DEFAULT_RATE_LIMIT])


# Lifespan: replace deprecated on_event startup/shutdown with a lifespan handler
from contextlib import asynccontextmanager
import warnings

# Suppress known deprecation warnings coming from third-party libs that we can't
# control (e.g. python-jose using datetime.utcnow()). Keep this minimal and
# targeted so it doesn't hide other issues.
warnings.filterwarnings("ignore", message=r"datetime.datetime.utcnow\(\) is deprecated")
# argon2 cffi exposes a deprecated attribute access that creates a lot of noise
warnings.filterwarnings("ignore", message=r"Accessing argon2.__version__ is deprecated")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Lifespan startup: initializing database and other resources")
    init_db()
    yield
    logger.info("Lifespan shutdown: cleaning up resources")

app = FastAPI(title="WorkHub Backend", version="1.0.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# CORS (developer friendly defaults)
origins = os.getenv("CORS_ORIGINS", "*")
if origins == "*":
    allowed_origins: List[str] = ["*"]
else:
    # comma separated list
    allowed_origins = [o.strip() for o in origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


from fastapi.exceptions import RequestValidationError
from app.errors import make_validation_error_response


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"error": {"code": "rate_limited", "message": "Rate limit exceeded"}})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Return a standardized validation error payload
    return JSONResponse(status_code=422, content=make_validation_error_response(exc.errors()))


@app.get("/api/health", tags=["Health"])
async def health() -> dict:
    return {"status": "ok"}


@app.post("/api/token")
async def token_alias() -> RedirectResponse:
    # Deprecated alias: redirect clients to the new login path
    return RedirectResponse(url="/api/auth/login", status_code=307)


def _include_router_if_available(module_name: str) -> None:
    try:
        module = importlib.import_module(module_name)
        router = getattr(module, "router", None)
        if router is None:
            logger.info("Module %s found but has no `router` attribute, skipping", module_name)
            return
        app.include_router(router)
        logger.info("Included router: %s", module_name)
    except ModuleNotFoundError:
        logger.info("Router module %s not found, skipping", module_name)
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.exception("Error while including router %s: %s", module_name, exc)


# Try to include known routers if they exist
for r in ("auth", "users", "tickets", "messages", "branches", "workgroups", "attachments"):
    _include_router_if_available(f"app.routers.{r}")

# Because `system` is development-only, import it explicitly so we get clear
# logging if something fails during import and ensure `/api/seed` is available.
try:
    from app.routers import system as _system_module

    if hasattr(_system_module, "router"):
        app.include_router(_system_module.router)
        logger.info("Explicitly included router: app.routers.system")
    else:
        logger.info("app.routers.system imported but has no `router` attribute; skipping")
except ModuleNotFoundError:
    logger.info("app.routers.system not found, skipping")
except Exception as exc:  # pragma: no cover - defensive logging
    logger.exception("Error while explicitly including system router: %s", exc)


__all__ = ["app"]
