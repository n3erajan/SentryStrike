import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.dependencies import analysis_queue, get_current_user, invite_service
from app.api.routes import analysis, auth, health, notifications, oast, reports, scan, workspace
from app.config import get_settings
from app.core.exceptions import AppError
from shared.database.connection import close_db, init_db
from shared.scan_queue import RedisScanQueue
from shared.utils.logger import configure_logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize infrastructure on startup and tear it down on shutdown."""
    settings = get_settings()
    configure_logging(log_level=settings.log_level)
    await init_db(settings)

    scan_queue = RedisScanQueue.from_settings(settings)
    scan.set_scan_queue(scan_queue)
    app.state.scan_queue = scan_queue
    try:
        yield
    finally:
        await invite_service.close()
        await analysis_queue.close()
        await scan_queue.close()
        await close_db()


def create_app() -> FastAPI:
    """Build, wire, and return the FastAPI application instance."""
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        debug=settings.app_debug,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(scan.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.include_router(analysis.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.include_router(reports.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.include_router(workspace.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.include_router(notifications.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])

    # OAST callback collaborator — unauthenticated by design (the tested target
    # is unauthenticated when its server-side fetch calls back). No /api/v1 prefix.
    app.include_router(oast.router)

    @app.exception_handler(AppError)
    async def app_error_handler(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": exc.message, "error_code": exc.code},
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"},
        )

    return app


app = create_app()
