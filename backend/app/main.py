"""Sentrix API — FastAPI application entry point.

Run from the repository root:  uvicorn backend.app.main:app --reload
Then open http://localhost:8000 (UI) or http://localhost:8000/api/docs (OpenAPI).
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .api.v1 import auth, email_identity, platform
from .core.config import ROOT_DIR, get_settings
from .core.logging import configure_logging
from .db.base import Base
from .db.session import SessionLocal, engine
from .services.email_identity import ownership
from .services.errors import ServiceError

log = logging.getLogger("sentrix")
settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging(settings.DEBUG)
    settings.assert_safe_for_production()
    from . import models  # noqa: F401 — register tables
    if settings.AUTO_CREATE_SCHEMA:
        Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if settings.SEED_DEMO_DATA:
            from .seed import seed_demo
            seed_demo(db)
        expired = ownership.expire_all(db)
    log.info("%s %s started (env=%s, email provider=%s, expired challenges=%d)", settings.APP_NAME,
             settings.APP_VERSION, settings.ENVIRONMENT, settings.EMAIL_PROVIDER, expired)
    yield


app = FastAPI(title=f"{settings.APP_NAME} API", version=settings.APP_VERSION, description=settings.APP_TAGLINE,
              docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                   allow_methods=["*"], allow_headers=["Authorization", "Content-Type"],
                   expose_headers=["X-Report-Id", "Content-Disposition"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")  # verification links never leak via Referer
    resp.headers.setdefault("X-Frame-Options", "DENY")
    if request.url.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.exception_handler(ServiceError)
async def _service_error(_: Request, exc: ServiceError):
    return JSONResponse({"detail": exc.message}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def _validation_error(_: Request, exc: RequestValidationError):
    msgs = [f"{'.'.join(str(p) for p in e['loc'][1:]) or 'body'}: {e['msg']}" for e in exc.errors()]
    return JSONResponse({"detail": "; ".join(msgs), "errors": [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]},
                        status_code=422)


@app.get("/api/healthz", tags=["meta"])
def healthz():
    return {"status": "ok", "service": settings.APP_NAME, "version": settings.APP_VERSION}


for r in (auth.router, email_identity.router, platform.router):
    app.include_router(r, prefix="/api/v1")

if settings.SERVE_FRONTEND and (ROOT_DIR / "ui-prototype").is_dir():
    app.mount("/", StaticFiles(directory=ROOT_DIR / "ui-prototype", html=True), name="ui")
