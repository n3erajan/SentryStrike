import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.dependencies import get_current_user
from app.api.routes import analysis, auth, health, reports, scan
from app.config import get_settings
from app.core.exceptions import AppError
from app.core.scanner import ScanOrchestrator
from app.database.connection import close_db, init_db
from app.database.repositories.scan_repository import ScanRepository
from app.utils.logger import configure_logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    await init_db()

    repository = ScanRepository()
    scanner_orchestrator = ScanOrchestrator(repository)
    scan.set_orchestrator(scanner_orchestrator)

    yield

    await close_db()


def create_app() -> FastAPI:
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
