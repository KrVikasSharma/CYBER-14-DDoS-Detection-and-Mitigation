from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.dependencies import get_auth_service, get_current_user
from app.auth.models import LocalUser, LoginRequest, TokenResponse
from app.auth.service import AuthService, AuthenticationError, LoginRateLimitError

router = APIRouter()


@router.post("/login", response_model=TokenResponse, summary="Create a local development access session")
async def login(request: LoginRequest, service: AuthService = Depends(get_auth_service)) -> TokenResponse:
    try:
        return service.login(request.username, request.password)
    except LoginRateLimitError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc


@router.get("/me", response_model=LocalUser)
async def me(user: LocalUser = Depends(get_current_user)) -> LocalUser:
    return user


@router.post("/logout")
async def logout(
    user: LocalUser = Depends(get_current_user),
    service: AuthService = Depends(get_auth_service),
) -> dict[str, str | bool]:
    return service.logout(user)
