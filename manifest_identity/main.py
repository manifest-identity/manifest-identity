"""Application entry point.

Subphase 1.2: operators, roles, sessions, and the audit spine, on the
1.1 foundation. Error discipline lives here: validation failures and
unhandled errors answer with fixed bodies that repeat nothing the
caller sent; the detail goes to the server log, never the response.
"""

import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from manifest_identity.authorize import routes_authorizations as authorize
from manifest_identity.authorize import routes_governance as governance
from manifest_identity.compare import routes_delta as compare
from manifest_identity.core import routes_admin as admin
from manifest_identity.core import routes_auth as auth
from manifest_identity.core.bootstrap import bootstrap_admin
from manifest_identity.core.config import get_settings
from manifest_identity.core.db import database_reachable, get_engine
from manifest_identity.core.logs import configure_logging, log_event
from manifest_identity.decide import routes_campaigns as campaigns
from manifest_identity.decide import routes_reports as reports
from manifest_identity.observe import routes_imports as imports
from manifest_identity.observe import routes_inventory as inventory

# The page is served from this application and fetches nothing from
# anywhere else, so the policy can forbid every external origin and
# every inline script. Inline is forbidden deliberately: it is the
# sink a stored value would have to reach to execute, and the frontend
# has no inline script or style for it to hide in.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self'; connect-src 'self'; font-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"


def create_app() -> FastAPI:
    settings = get_settings()  # missing required keys raise here, at boot
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        from sqlalchemy.orm import Session

        with Session(get_engine()) as db:
            bootstrap_admin(db, settings)
        yield

    app = FastAPI(title="manifest-identity", version="0.2.0", lifespan=lifespan)

    @app.middleware("http")
    async def access_log(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        started = time.monotonic()
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        log_event(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=round((time.monotonic() - started) * 1000, 1),
        )
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Field names and rules only: what the caller sent is never
        # repeated back, but which rule refused is named, because a
        # caller who cannot learn the rule reads the source instead.
        log_event("validation_rejected", path=request.url.path)
        fields = sorted(
            {
                ".".join(str(part) for part in err["loc"] if part != "body")
                + ": "
                + err["msg"]
                for err in exc.errors()
            }
        )
        return JSONResponse(
            status_code=422,
            content={"detail": "invalid request", "fields": fields},
        )

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        log_event("unhandled_error", path=request.url.path, include_traceback=True)
        return JSONResponse(status_code=500, content={"detail": "internal error"})

    @app.get("/health")
    def health() -> dict[str, str]:
        """Liveness: the process is up and serving."""
        return {"status": "ok"}

    @app.get("/health/database")
    def health_database(response: Response) -> dict[str, str]:
        """Readiness: the database answers a round trip."""
        if database_reachable():
            return {"status": "ok"}
        response.status_code = 503
        return {"status": "unavailable"}

    app.include_router(auth.router)
    app.include_router(admin.router)
    app.include_router(imports.router)
    app.include_router(inventory.router)
    app.include_router(governance.router)
    app.include_router(authorize.router)
    app.include_router(compare.router)
    app.include_router(campaigns.router)
    app.include_router(reports.router)

    # The shell and its assets are public; every value they display
    # arrives over the authenticated API.
    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(FRONTEND / "index.html")

    app.mount("/static", StaticFiles(directory=FRONTEND), name="static")
    return app


app = create_app()
