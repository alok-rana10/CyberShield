"""Main FastAPI application entrypoint for CyberShield."""

import logging
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.routes.auth import router as auth_router
from app.routes.findings import router as findings_router
from app.routes.dashboard import router as dashboard_router
from app.routes.headers import router as headers_router
from app.routes.fim import router as fim_router
from app.routes.logs import router as logs_router
from app.routes.scans import router as scans_router

logger = logging.getLogger("cybershield")


def create_app(custom_settings: Settings | None = None) -> FastAPI:
    """Create and configure a CyberShield FastAPI application instance."""
    cfg = custom_settings or get_settings()

    application = FastAPI(
        title=cfg.APP_NAME,
        description="CyberShield - Defensive Cybersecurity Monitoring & Assessment Platform",
        version="0.1.0",
        docs_url=f"{cfg.API_V1_PREFIX}/docs" if cfg.DEBUG else None,
        redoc_url=f"{cfg.API_V1_PREFIX}/redoc" if cfg.DEBUG else None,
    )

    # Configure CORS Middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins_list,
        allow_origin_regex=cfg.CORS_ORIGIN_REGEX if cfg.CORS_ORIGIN_REGEX else None,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include Routers
    application.include_router(auth_router, prefix=cfg.API_V1_PREFIX)
    application.include_router(findings_router, prefix=cfg.API_V1_PREFIX)
    application.include_router(dashboard_router, prefix=cfg.API_V1_PREFIX)
    application.include_router(headers_router, prefix=cfg.API_V1_PREFIX)
    application.include_router(fim_router, prefix=cfg.API_V1_PREFIX)
    application.include_router(logs_router, prefix=cfg.API_V1_PREFIX)
    application.include_router(scans_router, prefix=cfg.API_V1_PREFIX)

    @application.get(
        "/health",
        status_code=status.HTTP_200_OK,
        summary="Root Health Check",
        tags=["System"],
    )
    @application.get(
        f"{cfg.API_V1_PREFIX}/health",
        status_code=status.HTTP_200_OK,
        summary="API Health Check",
        tags=["System"],
    )
    async def health_check() -> dict:
        """Return application operational status and application name."""
        return {
            "status": "ok",
            "app": cfg.APP_NAME,
        }

    # Secure Error Handling without Information Disclosure
    @application.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle unexpected server errors without leaking internal stack traces."""
        if isinstance(exc, HTTPException):
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=getattr(exc, "headers", None) or {},
            )

        logger.error(
            "Unhandled server error on %s %s: %s",
            request.method,
            request.url.path,
            exc,
            exc_info=True,
        )
        detail = str(exc) if cfg.DEBUG else "An unexpected internal error occurred."
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": detail, "status": "error"},
        )

    return application


app = create_app()
