"""Routes package initialization."""

from app.routes.auth import router as auth_router
from app.routes.findings import router as findings_router
from app.routes.dashboard import router as dashboard_router
from app.routes.headers import router as headers_router
from app.routes.fim import router as fim_router

__all__ = [
    "auth_router",
    "findings_router",
    "dashboard_router",
    "headers_router",
    "fim_router",
]
