from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class UserRole(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"


class LocalUser(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    role: UserRole
    auth_mode: Literal["local_demo", "local_development"]


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class TokenResponse(BaseModel):
    access_token: str | None
    token_type: Literal["bearer"] = "bearer"
    expires_in_seconds: int | None
    auth_enabled: bool
    user: LocalUser


class SecurityEvent(BaseModel):
    event_type: str
    username: str | None = None
    role: UserRole | None = None
    success: bool
    reason: str
    correlation_id: str
