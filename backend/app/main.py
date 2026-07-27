import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.dependencies import analysis_queue, get_current_user, invite_service
from app.api.routes import applications, analysis, auth, health, notifications, oast, reports, scan, workspace
from app.config import get_settings
from app.core.exceptions import AppError
from shared.database.connection import close_db, init_db
from shared.scan_queue import RedisScanQueue
from shared.utils.logger import configure_logging

logger = logging.getLogger(__name__)


def _request_id(request: Request) -> str:
    """Return the server-generated support reference for this request."""
    return getattr(request.state, "request_id", uuid.uuid4().hex[:12])


def _validation_message(error: dict) -> str:
    """Translate Pydantic's implementation language into concise UI copy."""
    message = str(error.get("msg") or "Enter a valid value.")
    if message.startswith("Value error, "):
        message = message.removeprefix("Value error, ")
    if error.get("type") == "missing":
        return "This field is required."
    if error.get("type") in {"string_too_short", "too_short"}:
        minimum = error.get("ctx", {}).get("min_length")
        return f"Enter at least {minimum} characters." if minimum else "This value is too short."
    if error.get("type") in {"string_too_long", "too_long"}:
        maximum = error.get("ctx", {}).get("max_length")
        return f"Enter no more than {maximum} characters." if maximum else "This value is too long."
    return message[:240]


def _field_errors(exc: RequestValidationError) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    for error in exc.errors():
        location = [str(part) for part in error.get("loc", ()) if part not in {"body", "query", "path"}]
        errors.append(
            {
                "field": ".".join(location) or "request",
                "message": _validation_message(error),
            }
        )
    return errors


def _internal_error_response(request: Request, exc: Exception) -> JSONResponse:
    reference = _request_id(request)
    logger.exception("Unhandled exception [request_id=%s]", reference, exc_info=exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "message": "We couldn't complete your request. Please try again.",
            "error_code": "INTERNAL_ERROR",
            "request_id": reference,
        },
    )


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
        docs_url="/docs" if settings.app_debug else None,
        redoc_url="/redoc" if settings.app_debug else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_reference(request: Request, call_next):
        request.state.request_id = uuid.uuid4().hex[:12]
        try:
            response = await call_next(request)
        except Exception as exc:
            # Middleware is outside FastAPI's exception layer, so sanitize here
            # as well to prevent debug tracebacks from becoming HTTP responses.
            response = _internal_error_response(request, exc)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(applications.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.include_router(scan.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.include_router(analysis.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.include_router(reports.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.include_router(workspace.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.include_router(notifications.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])

    # OAST callback collaborator — unauthenticated by design (the tested target
    # is unauthenticated when its server-side fetch calls back). No /api/v1 prefix.
    app.include_router(oast.router)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "success": False,
                "message": "Check the highlighted fields and try again.",
                "error_code": "VALIDATION_ERROR",
                "field_errors": _field_errors(exc),
                "request_id": _request_id(request),
            },
        )

    @app.exception_handler(HTTPException)
    async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail
        message = (
            detail.get("message")
            if isinstance(detail, dict)
            else detail
            if isinstance(detail, str)
            else "The request could not be completed."
        )
        error_code = (
            detail.get("code")
            if isinstance(detail, dict)
            else f"HTTP_{exc.status_code}"
        )
        return JSONResponse(
            status_code=exc.status_code,
            headers=exc.headers,
            content={
                "success": False,
                "message": message,
                "error_code": error_code,
                "detail": detail,
                "request_id": _request_id(request),
            },
        )

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": exc.message,
                "error_code": exc.code,
                "request_id": _request_id(request),
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        return _internal_error_response(request, exc)

    return app


app = create_app()
