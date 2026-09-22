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
