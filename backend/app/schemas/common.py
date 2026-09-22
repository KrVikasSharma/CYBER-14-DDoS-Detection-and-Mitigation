from typing import Any

from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    error: str = Field(..., description="Machine-readable error type.")
    message: str = Field(..., description="Human-readable error message.")
    path: str | None = Field(default=None, description="Request path where the error occurred.")
    details: dict[str, Any] | None = Field(default=None, description="Optional structured details.")
