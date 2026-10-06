"""Unit tests for the health check endpoint."""

from fastapi.testclient import TestClient
from app.main import app
from app.config import get_settings

client = TestClient(app)
settings = get_settings()


def test_health_check_returns_200():
    """Verify that GET /api/v1/health returns HTTP 200 OK."""
    response = client.get(f"{settings.API_V1_PREFIX}/health")
    assert response.status_code == 200


def test_health_check_payload_structure():
    """Verify that response contains status='ok' and correct app name."""
    response = client.get(f"{settings.API_V1_PREFIX}/health")
    data = response.json()
    assert data.get("status") == "ok"
    assert data.get("app") == settings.APP_NAME
    assert data == {"status": "ok", "app": "CyberShield"}
