import pytest
from fastapi.testclient import TestClient

from app.auth.config import AuthSettings
from app.auth.models import LocalUser, UserRole
from app.auth.service import AuthService, AuthenticationError
from app.auth.tokens import InvalidTokenError, decode_access_token
from app.core.config import Settings
from app.main import create_app
from app.services.detection_service import get_detection_service
from app.services.streaming_service import get_streaming_service


def enabled_settings(password="correct horse battery staple"):
    return AuthSettings(
        auth_enabled=True,
        auth_secret_key="x" * 40,
        auth_bootstrap_username="admin",
        auth_bootstrap_password=password,
        auth_bootstrap_role="admin",
    )


def test_valid_login_returns_signed_token_and_user_without_hash():
    service = AuthService(enabled_settings())
    result = service.login("admin", "correct horse battery staple")
    assert result.access_token
    assert result.user.role is UserRole.ADMIN
    assert "password" not in result.model_dump()
    assert "hash" not in result.model_dump()


def test_invalid_and_unknown_credentials_are_generic():
    service = AuthService(enabled_settings())
    with pytest.raises(AuthenticationError, match="Invalid username or password"):
        service.login("admin", "wrong")
    with pytest.raises(AuthenticationError, match="Invalid username or password"):
        service.login("unknown", "wrong")
    assert all(event.reason == "Invalid credentials" for event in service.events)


def test_token_expiry_and_malformed_token_fail():
    service = AuthService(enabled_settings())
    token = service.login("admin", "correct horse battery staple").access_token
    with pytest.raises(InvalidTokenError):
        decode_access_token(token or "", "x" * 40, -1)
    with pytest.raises(InvalidTokenError):
        decode_access_token("not-a-token", "x" * 40, 1800)


def test_missing_enabled_secret_fails_closed():
    with pytest.raises(ValueError, match="AUTH_SECRET_KEY"):
        AuthSettings(auth_enabled=True, auth_bootstrap_password="password").validate_enabled_configuration()


def test_roles_are_enforced_on_protected_routes(monkeypatch, workspace_tmp_path):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_SECRET_KEY", "y" * 40)
    monkeypatch.setenv("AUTH_BOOTSTRAP_PASSWORD", "password")
    monkeypatch.setenv("AUTH_BOOTSTRAP_ROLE", "viewer")
    from app.auth.config import get_auth_settings
    from app.auth.dependencies import get_auth_service
    get_auth_settings.cache_clear()
    get_auth_service.cache_clear()
    application = create_app()
    application.dependency_overrides[get_detection_service] = lambda: object()
    application.dependency_overrides[get_streaming_service] = lambda: object()
    client = TestClient(application)
    token = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"}).json()["access_token"]
    response = client.post(
        "/api/v1/detection/analyze",
        headers={"Authorization": f"Bearer {token}"},
        json={"source_identifier": "test", "features": {"x": 1}},
    )
    assert response.status_code == 403
    get_auth_settings.cache_clear()
    get_auth_service.cache_clear()


def test_auth_disabled_preserves_development_identity():
    service = AuthService(AuthSettings(auth_enabled=False))
    result = service.login("anything", "anything")
    assert result.auth_enabled is False
    assert result.user.auth_mode == "local_development"
    assert result.user.role is UserRole.ADMIN


def test_auth_endpoints_support_me_logout_and_reject_missing_token(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_SECRET_KEY", "z" * 40)
    monkeypatch.setenv("AUTH_BOOTSTRAP_PASSWORD", "password")
    monkeypatch.setenv("AUTH_BOOTSTRAP_ROLE", "admin")
    from app.auth.config import get_auth_settings
    from app.auth.dependencies import get_auth_service
    get_auth_settings.cache_clear()
    get_auth_service.cache_clear()
    client = TestClient(create_app())
    assert client.get("/api/v1/auth/me").status_code == 401
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
    assert login.status_code == 200
    token = login.json()["access_token"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["role"] == "admin"
    logout = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout.status_code == 200
    assert "token" not in logout.json().get("token_revocation", "")
    get_auth_settings.cache_clear()
    get_auth_service.cache_clear()


def test_extract_client_ip_proxy_headers():
    from starlette.requests import Request
    from app.auth.dependencies import extract_client_ip

    # None fallback
    assert extract_client_ip(None) == "127.0.0.1"

    # CF-Connecting-IP
    scope_cf = {"type": "http", "headers": [(b"cf-connecting-ip", b"203.0.113.10")]}
    assert extract_client_ip(Request(scope_cf)) == "203.0.113.10"

    # X-Real-IP
    scope_real = {"type": "http", "headers": [(b"x-real-ip", b"198.51.100.25")]}
    assert extract_client_ip(Request(scope_real)) == "198.51.100.25"

    # X-Forwarded-For with single IP
    scope_xff_single = {"type": "http", "headers": [(b"x-forwarded-for", b"192.0.2.1")]}
    assert extract_client_ip(Request(scope_xff_single)) == "192.0.2.1"

    # X-Forwarded-For with chained IPs (client, proxy1, proxy2)
    scope_xff_chain = {"type": "http", "headers": [(b"x-forwarded-for", b"192.0.2.99, 10.0.0.1, 172.16.0.2")]}
    assert extract_client_ip(Request(scope_xff_chain)) == "192.0.2.99"

    # Fallback to direct client host
    scope_direct = {"type": "http", "headers": [], "client": ("198.51.100.88", 54321)}
    assert extract_client_ip(Request(scope_direct)) == "198.51.100.88"


def test_distinct_client_ips_recorded_in_auth_events(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_SECRET_KEY", "w" * 40)
    monkeypatch.setenv("AUTH_BOOTSTRAP_PASSWORD", "password")
    monkeypatch.setenv("AUTH_BOOTSTRAP_ROLE", "admin")
    from app.auth.config import get_auth_settings
    from app.auth.dependencies import get_auth_service
    get_auth_settings.cache_clear()
    get_auth_service.cache_clear()

    application = create_app()
    client = TestClient(application)

    # Client A logs in from 203.0.113.50
    resp_a = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "password"},
        headers={"X-Forwarded-For": "203.0.113.50, 10.0.0.1"},
    )
    assert resp_a.status_code == 200
    token_a = resp_a.json()["access_token"]

    # Client A logs out
    client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token_a}", "X-Forwarded-For": "203.0.113.50"})

    # Client B logs in from 198.51.100.75
    resp_b = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "password"},
        headers={"X-Real-IP": "198.51.100.75"},
    )
    assert resp_b.status_code == 200

    service = get_auth_service()
    events = service.events
    assert len(events) >= 3
    login_events = [e for e in events if e.event_type == "login_success"]
    assert login_events[-2].client_ip == "203.0.113.50"
    assert login_events[-1].client_ip == "198.51.100.75"

    get_auth_settings.cache_clear()
    get_auth_service.cache_clear()


def test_single_active_login_enforcement(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_SECRET_KEY", "s" * 40)
    monkeypatch.setenv("AUTH_BOOTSTRAP_PASSWORD", "password")
    monkeypatch.setenv("AUTH_BOOTSTRAP_ROLE", "admin")
    from app.auth.config import get_auth_settings
    from app.auth.dependencies import get_auth_service
    get_auth_settings.cache_clear()
    get_auth_service.cache_clear()

    application = create_app()
    client = TestClient(application)

    # 1. First login succeeds
    resp1 = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "password"},
        headers={"X-Forwarded-For": "203.0.113.10"},
    )
    assert resp1.status_code == 200
    token1 = resp1.json()["access_token"]

    # 2. Second login for same username from another client is REJECTED
    resp2 = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "password"},
        headers={"X-Forwarded-For": "198.51.100.20"},
    )
    assert resp2.status_code == 409
    error_msg = resp2.json().get("message") or resp2.json().get("detail") or ""
    assert "User already has an active session. Please logout from the existing session first." in error_msg

    # 3. First session still works normally
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token1}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "admin"

    # 4. Explicit logout releases session
    logout_resp = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token1}"})
    assert logout_resp.status_code == 200

    # 5. Now second client can log in
    resp3 = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "password"},
        headers={"X-Forwarded-For": "198.51.100.20"},
    )
    assert resp3.status_code == 200
    assert resp3.json()["access_token"] is not None

    get_auth_settings.cache_clear()
    get_auth_service.cache_clear()


def test_expired_session_allows_new_login():
    settings = AuthSettings(
        auth_enabled=True,
        auth_secret_key="e" * 40,
        auth_bootstrap_username="admin",
        auth_bootstrap_password="password",
        auth_bootstrap_role="admin",
        auth_access_token_expire_minutes=1,
    )
    service = AuthService(settings)

    # First login
    res1 = service.login("admin", "password", client_ip="203.0.113.10")
    assert res1.access_token

    # Simulate token expiration in active sessions
    service._active_sessions["admin"]["expires_at"] = 0.0

    # Second login should now succeed because previous session expired
    res2 = service.login("admin", "password", client_ip="198.51.100.20")
    assert res2.access_token
    assert service._active_sessions["admin"]["client_ip"] == "198.51.100.20"


def test_traffic_simulation_ip_unaffected_by_client_ip(monkeypatch):
    """Verify that DDoS simulation flow IP (192.168.1.50) is never overwritten by client IP."""
    import json
    from pathlib import Path
    from app.core.config import Settings
    from app.schemas.detection import DetectionAnalyzeRequest
    from app.services.detection_service import DetectionService

    demo_path = Path("data/demo/demo_scenarios.json")
    if demo_path.exists():
        with open(demo_path, encoding="utf-8") as f:
            scenarios = json.load(f)
        features = scenarios.get("benign", {}).get("features", {})
    else:
        features = {}

    settings = Settings(demo_mode=True)
    service = DetectionService(settings)
    req = DetectionAnalyzeRequest(
        source_identifier="192.168.1.50",
        traffic_rate=10.0,
        features=features,
    )
    res = service.analyze(req)
    assert res.metadata.source_ip == "192.168.1.50"


