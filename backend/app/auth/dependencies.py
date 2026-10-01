from typing import Annotated
from functools import lru_cache

from fastapi import Depends, Header, HTTPException, Request, status

from app.auth.config import get_auth_settings
from app.auth.models import LocalUser, UserRole
from app.auth.service import AuthService
from app.auth.tokens import InvalidTokenError, decode_access_token


def extract_client_ip(request: Request | None = None) -> str:
    """Extract real client IP address from proxy headers (Cloudflare/Render/Vercel) or fallback."""
    if request is None:
        return "127.0.0.1"

    # 1. Cloudflare connecting IP
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip and cf_ip.strip():
        return cf_ip.strip()

    # 2. X-Real-IP header
    real_ip = request.headers.get("x-real-ip")
    if real_ip and real_ip.strip():
        return real_ip.strip()

    # 3. X-Forwarded-For header (first IP in chain is origin client)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for and forwarded_for.strip():
        client_ip = forwarded_for.split(",")[0].strip()
        if client_ip:
            return client_ip

    # 4. Direct client connection host
    if request.client and request.client.host:
        return request.client.host.strip()

    return "127.0.0.1"


@lru_cache
def get_auth_service() -> AuthService:
    return AuthService(get_auth_settings())


def get_current_user(authorization: Annotated[str | None, Header()] = None) -> LocalUser:
    settings = get_auth_settings()
    if not settings.auth_enabled:
        return LocalUser(username="development", role=UserRole.ADMIN, auth_mode="local_development")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    try:
        user = decode_access_token(token, settings.auth_secret_key or "", settings.auth_access_token_expire_minutes * 60)
        try:
            service = get_auth_service()
            service.touch_session(user.username)
        except Exception:
            pass
        return user
    except InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired access token", headers={"WWW-Authenticate": "Bearer"}) from exc


def require_roles(*roles: UserRole):
    def dependency(user: Annotated[LocalUser, Depends(get_current_user)]) -> LocalUser:
        if user.auth_mode == "local_development":
            return user
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user
    return dependency
