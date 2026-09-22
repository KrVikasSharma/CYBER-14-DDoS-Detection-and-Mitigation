from typing import Annotated
from functools import lru_cache

from fastapi import Depends, Header, HTTPException, status

from app.auth.config import get_auth_settings
from app.auth.models import LocalUser, UserRole
from app.auth.service import AuthService
from app.auth.tokens import InvalidTokenError, decode_access_token


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
        return decode_access_token(token, settings.auth_secret_key or "", settings.auth_access_token_expire_minutes * 60)
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
