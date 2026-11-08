import os
from datetime import date, datetime, timezone

from sqlalchemy import JSON, BigInteger, CheckConstraint, Date, DateTime, ForeignKey, Integer, String, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///devicetrust.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 10} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Device(Base):
    __tablename__ = "devices"
    device_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    manufacturer: Mapped[str] = mapped_column(String(100))
    model: Mapped[str] = mapped_column(String(100))
    firmware_version: Mapped[str] = mapped_column(String(50))
    support_until: Mapped[date | None] = mapped_column(Date, nullable=True)
    security: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidenceObservation(Base):
    __tablename__ = "evidence_observations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.device_id"), nullable=True, index=True
    )
    source_type: Mapped[str] = mapped_column(String(32))
    attribute: Mapped[str] = mapped_column(String(80), index=True)
    value: Mapped[str] = mapped_column(String(1000))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    confidence: Mapped[str] = mapped_column(String(10), default="low")
    verification_status: Mapped[str] = mapped_column(String(16), default="unverified")
    evidence_reference: Mapped[str | None] = mapped_column(String(500), nullable=True)
    evidence_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (UniqueConstraint("device_id", "component", "version", "vuln_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.device_id"), index=True)
    component: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(100))
    vuln_id: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20))
    fixed_in: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="open")
    justification: Mapped[str | None] = mapped_column(String(1000), nullable=True)


class AuditEntry(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[str] = mapped_column(String(40))
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(60))
    entity: Mapped[str] = mapped_column(String(120))
    payload: Mapped[dict] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class AuditChainState(Base):
    __tablename__ = "audit_chain_state"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_audit_chain_state_singleton"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)


class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    manufacturer: Mapped[str] = mapped_column(String(200))
    product_name: Mapped[str] = mapped_column(String(200))
    external_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProductRelease(Base):
    __tablename__ = "product_releases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), index=True)
    version: Mapped[str] = mapped_column(String(100))
    hardware_revision: Mapped[str | None] = mapped_column(String(100), nullable=True)
    release_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SBOMImport(Base):
    __tablename__ = "sbom_imports"
    __table_args__ = (
        UniqueConstraint(
            "product_release_id",
            "format",
            "content_sha256",
            name="uq_sbom_import_release_format_digest",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    product_release_id: Mapped[int] = mapped_column(ForeignKey("product_releases.id"), index=True)
    format: Mapped[str] = mapped_column(String(32))
    spec_version: Mapped[str] = mapped_column(String(20))
    source_type: Mapped[str] = mapped_column(String(32))
    source_reference: Mapped[str | None] = mapped_column(String(500), nullable=True)
    content_sha256: Mapped[str] = mapped_column(String(64))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    parser_version: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(16), default="accepted")
    component_count: Mapped[int] = mapped_column(Integer)
    validation_summary: Mapped[dict] = mapped_column(JSON, default=dict)


class SBOMComponent(Base):
    __tablename__ = "sbom_components"
    __table_args__ = (
        UniqueConstraint("sbom_import_id", "ordinal", name="uq_sbom_component_import_ordinal"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sbom_import_id: Mapped[int] = mapped_column(ForeignKey("sbom_imports.id"), index=True)
    ordinal: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(100))
    purl: Mapped[str | None] = mapped_column(String(512), nullable=True)


class ProductFinding(Base):
    __tablename__ = "product_findings"
    __table_args__ = (
        UniqueConstraint(
            "sbom_component_id",
            "vuln_id",
            "source",
            name="uq_product_finding_component_vuln_source",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sbom_component_id: Mapped[int] = mapped_column(ForeignKey("sbom_components.id"), index=True)
    vuln_id: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20))
    fixed_in: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="open")
    justification: Mapped[str | None] = mapped_column(String(1000), nullable=True)



class SBOMAssessment(Base):
    __tablename__ = "sbom_assessments"
    __table_args__ = (
        UniqueConstraint(
            "sbom_import_id",
            "request_key_hash",
            name="uq_sbom_assessment_import_request",
        ),
        CheckConstraint(
            "status IN ('disabled', 'complete', 'incomplete')",
            name="ck_sbom_assessment_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sbom_import_id: Mapped[int] = mapped_column(ForeignKey("sbom_imports.id"), index=True)
    request_key_hash: Mapped[str] = mapped_column(String(64))
    source_fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    component_count: Mapped[int] = mapped_column(Integer)
    finding_count: Mapped[int] = mapped_column(Integer)
    enrichment_metadata: Mapped[dict] = mapped_column(JSON, default=dict)


class SBOMAssessmentFinding(Base):
    __tablename__ = "sbom_assessment_findings"
    __table_args__ = (
        UniqueConstraint(
            "assessment_id",
            "sbom_component_id",
            "vuln_id",
            "source",
            name="uq_sbom_assessment_finding_identity",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("sbom_assessments.id"), index=True)
    sbom_component_id: Mapped[int] = mapped_column(ForeignKey("sbom_components.id"), index=True)
    vuln_id: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20))
    fixed_in: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source: Mapped[str] = mapped_column(String(20))
