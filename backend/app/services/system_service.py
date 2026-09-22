from app.core.config import Settings, get_settings
from app.auth.config import get_auth_settings
from app.schemas.system import SystemStatusResponse
from app.services.detection_service import DetectionService, get_detection_service


class SystemService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def get_status(self) -> SystemStatusResponse:
        auth = get_auth_settings()
        try:
            DetectionService(self._settings)
            if getattr(self._settings, "demo_mode", False):
                ml_status = "ready_demo_sample"
            elif self._settings.o2_fixture_only or self._settings.o3_fixture_only:
                ml_status = "ready_fixture_only"
            else:
                ml_status = "ready"
            streaming_status = "ready"
        except Exception:
            ml_status = "unavailable"
            streaming_status = "unavailable"
        return SystemStatusResponse(
            service=self._settings.app_name,
            environment=self._settings.app_env,
            status="ok",
            api_version=self._settings.api_v1_prefix,
            ml_status=ml_status,
            mitigation_status="simulation_only_ready",
            streaming_status=streaming_status,
            authentication_enabled=auth.auth_enabled,
            authentication_mode="local_demo" if auth.auth_enabled else "local_development",
            configured_roles=["viewer", "analyst", "operator", "admin"],
            simulator_enabled=self._settings.stream_simulator_enabled,
        )


def get_system_service() -> SystemService:
    return SystemService(get_settings())
