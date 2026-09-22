from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CYBER-14 DDoS Detection and Mitigation"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    log_level: str = "INFO"
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
    )
    secret_key: str = "change-me-in-local-env"
    o2_model_path: Path | None = None
    o3_model_path: Path | None = None
    o2_fixture_only: bool = False
    o3_fixture_only: bool = False
    demo_mode: bool = False
    demo_o2_model_path: Path = Path("data/demo/models/o2/model.joblib")
    demo_o3_model_path: Path = Path("data/demo/models/o3/model.joblib")
    websocket_max_message_bytes: int = 16_384
    websocket_max_messages_per_second: int = 10
    websocket_idle_timeout_seconds: int = 60
    stream_simulator_enabled: bool = False
    database_url: str = Field(default="mysql+pymysql://root:root@127.0.0.1:3306/cyber14_ddos")
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_recycle: int = 3600
    db_ssl_required: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
