from datetime import date, datetime, timezone
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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


class EvidenceObservationIn(BaseModel):
    """A bounded observation; clients cannot self-assert verification."""

    model_config = ConfigDict(extra="forbid")
    device_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    source_type: Literal["manual", "router_import", "network_observation", "sbom", "firmware", "vendor_api"]
    attribute: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,79}$")
    value: str = Field(min_length=1, max_length=1000)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: Literal["low", "medium", "high"] = "low"
    evidence_reference: str | None = Field(default=None, max_length=500)
    evidence_hash: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")

    @field_validator("observed_at")
    @classmethod
    def observed_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value.astimezone(timezone.utc)


class TriageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "in_progress", "fixed", "accepted_risk", "not_affected"]
    justification: str = Field(min_length=10, max_length=1000)


class ProductIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    manufacturer: str = Field(min_length=1, max_length=200)
    product_name: str = Field(min_length=1, max_length=200)
    external_reference: str | None = Field(default=None, max_length=255)


class ProductReleaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(min_length=1, max_length=100)
    hardware_revision: str | None = Field(default=None, max_length=100)
    release_reference: str | None = Field(default=None, max_length=255)


class SBOMImportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    product_release_id: int = Field(gt=0)
    source_type: Literal["manual", "pipeline"] = "manual"
    source_reference: str | None = Field(default=None, max_length=500)



class VulnerabilityDecisionIn(BaseModel):
    """A human-reviewed decision for one immutable assessment finding."""

    model_config = ConfigDict(extra="forbid")

    state: Literal[
        "resolved",
        "resolved_with_pedigree",
        "exploitable",
        "in_triage",
        "false_positive",
        "not_affected",
    ]
    justification: Literal[
        "code_not_present",
        "code_not_reachable",
        "requires_configuration",
        "requires_dependency",
        "requires_environment",
        "protected_by_compiler",
        "protected_at_runtime",
        "protected_at_perimeter",
        "protected_by_mitigating_control",
    ] | None = None
    detail: str = Field(min_length=20, max_length=4000)
    evidence_references: list[str] = Field(default_factory=list, max_length=10)
    responses: list[
        Literal[
            "can_not_fix",
            "will_not_fix",
            "update",
            "rollback",
            "workaround_available",
        ]
    ] = Field(default_factory=list, max_length=5)

    @field_validator("detail")
    @classmethod
    def detail_must_be_meaningful(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 20:
            raise ValueError("detail must contain at least 20 non-whitespace characters")
        return normalized

    @field_validator("evidence_references")
    @classmethod
    def evidence_references_must_be_bounded(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            item = value.strip()
            if not item or len(item) > 500 or any(ord(char) < 32 for char in item):
                raise ValueError("evidence references must be non-empty bounded identifiers")
            try:
                parsed = urlsplit(item)
            except ValueError:
                raise ValueError("evidence reference is malformed") from None
            sensitive_query_keys = {
                "access_token",
                "api_key",
                "key",
                "password",
                "secret",
                "sig",
                "signature",
                "token",
            }
            if parsed.scheme in {"http", "https"} and (
                parsed.username is not None
                or parsed.password is not None
                or any(
                    key.lower() in sensitive_query_keys
                    for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
                )
            ):
                raise ValueError("evidence references must not contain credentials or tokens")
            if item in normalized:
                raise ValueError("evidence references must be unique")
            normalized.append(item)
        return normalized

    @field_validator("responses")
    @classmethod
    def responses_must_be_unique(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("responses must be unique")
        return values

    @model_validator(mode="after")
    def not_affected_requires_justification_and_evidence(self):
        if self.state == "not_affected":
            if self.justification is None:
                raise ValueError("not_affected requires a CycloneDX justification")
            if not self.evidence_references:
                raise ValueError("not_affected requires at least one evidence reference")
        if self.state == "resolved_with_pedigree" and not self.evidence_references:
            raise ValueError("resolved_with_pedigree requires a pedigree evidence reference")
        return self


class DecisionEvidenceManifestIn(BaseModel):
    """Bind existing evidence artifact IDs to one immutable decision revision."""

    model_config = ConfigDict(extra="forbid")
    artifact_ids: list[str] = Field(min_length=1, max_length=10)

    @field_validator("artifact_ids")
    @classmethod
    def artifact_ids_must_be_unique_uuids(cls, values: list[str]) -> list[str]:
        import re

        if len(values) != len(set(values)):
            raise ValueError("artifact IDs must be unique")
        if any(re.fullmatch(r"[0-9a-fA-F-]{36}", value) is None for value in values):
            raise ValueError("artifact IDs must be UUIDs")
        return values


class DecisionSignatureIn(BaseModel):
    """A detached Ed25519 signature; private key material is never accepted."""

    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(min_length=36, max_length=36)
    signature: str = Field(pattern=r"^[A-Za-z0-9+/]{86}==$")


class DecisionApprovalIn(BaseModel):
    """An independent approval signature over a server-issued, timestamped envelope."""

    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(min_length=36, max_length=36)
    approved_at: datetime
    signature: str = Field(pattern=r"^[A-Za-z0-9+/]{86}==$")

    @field_validator("approved_at")
    @classmethod
    def approved_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approved_at must include a timezone")
        return value.astimezone(timezone.utc)
