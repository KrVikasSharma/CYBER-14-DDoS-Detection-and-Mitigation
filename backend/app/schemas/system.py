from pydantic import BaseModel, Field


class SystemStatusResponse(BaseModel):
    service: str = Field(..., description="Application service name.")
    environment: str = Field(..., description="Runtime environment.")
    status: str = Field(..., description="System status.")
    api_version: str = Field(..., description="Active API version prefix.")
    ml_status: str = Field(..., description="Current ML subsystem readiness.")
    mitigation_status: str = Field(..., description="Current mitigation subsystem readiness.")
    streaming_status: str = Field(..., description="Current streaming subsystem readiness.")
    authentication_enabled: bool = Field(..., description="Whether local authentication enforcement is enabled.")
    authentication_mode: str = Field(..., description="Non-secret authentication mode.")
    configured_roles: list[str] = Field(..., description="Configured role vocabulary.")
    simulator_enabled: bool = Field(..., description="Whether the controlled simulator is enabled.")
