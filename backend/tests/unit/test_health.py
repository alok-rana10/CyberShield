"""Unit tests for the health check endpoint."""

from fastapi.testclient import TestClient
from app.main import app, create_app
from app.config import Settings, get_settings

client = TestClient(app)
settings = get_settings()

PROD_ORIGIN = "https://cybershield-frontend-dj4s.onrender.com"
prod_app = create_app(Settings(CORS_ORIGINS=PROD_ORIGIN))
prod_client = TestClient(prod_app)


def test_health_check_returns_200():
    """Verify that GET /api/v1/health returns HTTP 200 OK."""
    response = client.get(f"{settings.API_V1_PREFIX}/health")
    assert response.status_code == 200


def test_root_health_check_returns_200():
    """Verify that root GET /health returns HTTP 200 OK."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "app": settings.APP_NAME}


def test_health_check_payload_structure():
    """Verify that response contains status='ok' and correct app name."""
    response = client.get(f"{settings.API_V1_PREFIX}/health")
    data = response.json()
    assert data.get("status") == "ok"
    assert data.get("app") == settings.APP_NAME
    assert data == {"status": "ok", "app": "CyberShield"}


def test_health_check_cors_allows_localhost_origin():
    """Verify that requests from localhost origin receive ACAO header in dev."""
    origin = "http://localhost:5173"
    response = client.get(
        f"{settings.API_V1_PREFIX}/health",
        headers={"Origin": origin},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == origin
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_production_cors_allows_exact_deployed_frontend_origin():
    """Verify that production backend allows requests from exact deployed frontend origin."""
    response = prod_client.get(
        f"{settings.API_V1_PREFIX}/health",
        headers={"Origin": PROD_ORIGIN},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == PROD_ORIGIN
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_production_cors_options_preflight_for_deployed_frontend():
    """Verify that OPTIONS preflight for exact deployed frontend returns 200 with CORS headers."""
    response = prod_client.options(
        f"{settings.API_V1_PREFIX}/health",
        headers={
            "Origin": PROD_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == PROD_ORIGIN
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_auth_register_cors_options_preflight_for_deployed_frontend():
    """Verify that POST preflight to /auth/register from exact deployed frontend succeeds."""
    response = prod_client.options(
        f"{settings.API_V1_PREFIX}/auth/register",
        headers={
            "Origin": PROD_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == PROD_ORIGIN
    assert response.headers.get("access-control-allow-credentials") == "true"
    assert "POST" in response.headers.get("access-control-allow-methods", "")


def test_production_cors_rejects_unrelated_render_subdomain():
    """Verify that unrelated/untrusted Render subdomains are strictly rejected."""
    untrusted_render_origin = "https://untrusted-app.onrender.com"
    # GET request does not include ACAO
    get_res = prod_client.get(
        f"{settings.API_V1_PREFIX}/health",
        headers={"Origin": untrusted_render_origin},
    )
    assert get_res.status_code == 200
    assert get_res.headers.get("access-control-allow-origin") is None

    # Preflight OPTIONS is rejected with 400
    opt_res = prod_client.options(
        f"{settings.API_V1_PREFIX}/auth/register",
        headers={
            "Origin": untrusted_render_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert opt_res.status_code == 400
    assert opt_res.headers.get("access-control-allow-origin") is None


def test_cors_rejects_arbitrary_unauthorized_origin():
    """Verify arbitrary unauthorized origins do not receive ACAO and preflight returns 400."""
    origin = "https://malicious-site.example.com"
    get_res = prod_client.get(
        f"{settings.API_V1_PREFIX}/health",
        headers={"Origin": origin},
    )
    assert get_res.status_code == 200
    assert get_res.headers.get("access-control-allow-origin") is None

    opt_res = prod_client.options(
        f"{settings.API_V1_PREFIX}/auth/register",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert opt_res.status_code == 400
    assert opt_res.headers.get("access-control-allow-origin") is None
