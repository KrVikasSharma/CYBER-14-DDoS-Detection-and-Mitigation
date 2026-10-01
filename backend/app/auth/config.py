from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthSettings(BaseSettings):
    auth_enabled: bool = False
    auth_secret_key: str | None = None
    auth_access_token_expire_minutes: int = Field(default=30, ge=1, le=1440)
    auth_bootstrap_username: str = "admin"
    auth_bootstrap_password: str | None = None
    auth_bootstrap_role: str = "admin"
    auth_login_max_attempts_per_minute: int = Field(default=10, ge=1, le=100)
    auth_session_idle_timeout_minutes: int = Field(default=15, ge=1, le=1440)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    def validate_enabled_configuration(self) -> None:
        if not self.auth_enabled:
            return
        if not self.auth_secret_key or len(self.auth_secret_key) < 32:
            raise ValueError("AUTH_SECRET_KEY must be set to at least 32 characters when authentication is enabled")
        if not self.auth_bootstrap_password:
            raise ValueError("AUTH_BOOTSTRAP_PASSWORD is required when authentication is enabled")
        if self.auth_bootstrap_role not in {"viewer", "analyst", "operator", "admin"}:
            raise ValueError("AUTH_BOOTSTRAP_ROLE must be viewer, analyst, operator, or admin")


@lru_cache
def get_auth_settings() -> AuthSettings:
    settings = AuthSettings()
    settings.validate_enabled_configuration()
    return settings
