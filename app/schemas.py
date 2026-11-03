from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ManagementInterface(BaseModel):
    """Declared management-plane interface; nullable exposure means unknown."""

    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    protocol: str = Field(min_length=1, max_length=40)
    internet_exposed: bool | None = None
    authentication_required: bool | None = None


class SecurityProfile(BaseModel):
    """Declared security attributes. None = unknown (never assumed compliant)."""

    model_config = ConfigDict(extra="forbid")
    unique_identity: bool | None = None
    authentication: Literal["none", "password_default", "password_custom", "device_certificate"] | None = None
    default_credentials: bool | None = None
    open_interfaces: list[str] | None = Field(default=None, max_length=50)
    internet_exposed: bool | None = None
    management_interfaces: list[ManagementInterface] | None = Field(default=None, max_length=20)
    encryption_in_transit: bool | None = None
    encryption_at_rest: bool | None = None
    update_mechanism: Literal["none", "manual", "automatic_unsigned", "automatic_signed"] | None = None
    logging_enabled: bool | None = None
    secure_boot: bool | None = None
    firmware_signed: bool | None = None


class DeviceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    manufacturer: str = Field(min_length=1, max_length=100)
    model: str = Field(min_length=1, max_length=100)
    firmware_version: str = Field(min_length=1, max_length=50)
    support_until: date | None = None
    security: SecurityProfile = Field(default_factory=SecurityProfile)


class TriageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "in_progress", "fixed", "accepted_risk", "not_affected"]
    justification: str = Field(min_length=10, max_length=1000)
