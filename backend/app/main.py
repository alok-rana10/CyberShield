"""Main FastAPI application entrypoint for CyberShield."""

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.routes.auth import router as auth_router
from app.routes.findings import router as findings_router
from app.routes.dashboard import router as dashboard_router
from app.routes.headers import router as headers_router
from app.routes.fim import router as fim_router

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    description="CyberShield - Defensive Cybersecurity Monitoring & Assessment Platform",
    version="0.1.0",
    docs_url=f"{settings.API_V1_PREFIX}/docs" if settings.DEBUG else None,
    redoc_url=f"{settings.API_V1_PREFIX}/redoc" if settings.DEBUG else None,
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth_router, prefix=settings.API_V1_PREFIX)
app.include_router(findings_router, prefix=settings.API_V1_PREFIX)
app.include_router(dashboard_router, prefix=settings.API_V1_PREFIX)
app.include_router(headers_router, prefix=settings.API_V1_PREFIX)
app.include_router(fim_router, prefix=settings.API_V1_PREFIX)


@app.get(
    f"{settings.API_V1_PREFIX}/health",
    status_code=status.HTTP_200_OK,
    summary="Health Check",
    tags=["System"],
)
async def health_check() -> dict:
    """Return application operational status and application name."""
    return {
        "status": "ok",
        "app": settings.APP_NAME,
    }


# Basic Secure Error Handling
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected server errors without leaking internal stack traces."""
    detail = str(exc) if settings.DEBUG else "An unexpected internal error occurred."
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": detail, "status": "error"},
    )
