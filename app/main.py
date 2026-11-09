import hmac
import json
import os
from datetime import timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from . import audit, identity, posture, product_sbom, sbom, vulnerability_decisions
from .db import (
    AuditEntry,
    Device,
    EvidenceObservation,
    ProductFinding,
    ProductRelease,
    SBOMComponent,
    SBOMImport,
    SessionLocal,
    Vulnerability,
)
from .evidence_normalization import NORMALIZER_VERSION, normalize_observation
from .schemas import (
    DeviceIn,
    EvidenceObservationIn,
    ProductIn,
    ProductReleaseIn,
    SecurityProfile,
    TriageIn,
    VulnerabilityDecisionIn,
)

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
MAX_SBOM_BYTES = 2 * 1024 * 1024


app = FastAPI(title="DeviceTrust", version="0.2.0")
WEB_DIR = Path(__file__).resolve().parent.parent / "web"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path == "/" or request.url.path.startswith("/assets/"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", include_in_schema=False)
def operator_console():
    return FileResponse(WEB_DIR / "index.html")


app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")


def get_db():
    with SessionLocal() as db:
        yield db


def auth(request: Request, x_api_key: str = Header(default="", alias="X-API-Key")) -> str:
    mode = os.getenv("DEVICETRUST_AUTH_MODE", "legacy").strip().lower()
    required = identity.required_scopes(request.method, request.url.path)
    if required is None:
        raise HTTPException(403, "No authorization policy is defined for this route")

    if mode == "legacy":
        expected = os.getenv("DEVICETRUST_API_KEY")
        if not expected:
            raise HTTPException(503, "Legacy API key is not configured")
        if not hmac.compare_digest(x_api_key.encode(), expected.encode()):
            raise HTTPException(401, "Invalid API credential")
        return "api-key"

    if mode != "managed":
        raise HTTPException(503, "Unsupported authentication mode")
    if not x_api_key:
        raise HTTPException(401, "Missing API credential")

    try:
        with SessionLocal() as db:
            principal = identity.authenticate(db, x_api_key)
    except identity.IdentityConfigurationError:
        raise HTTPException(503, "Managed authentication configuration is unavailable") from None
    except SQLAlchemyError:
        raise HTTPException(503, "Managed authentication is unavailable") from None

    if principal is None:
        raise HTTPException(401, "Invalid API credential")
    if not required.issubset(principal.scopes):
        raise HTTPException(403, "Insufficient API credential scope")
    return f"principal:{principal.principal_id}"


def get_write_db(_: str = Depends(auth)):
    """Acquire the audit writer lock after authentication and before route reads."""
    with SessionLocal() as db:
        audit.acquire_chain_lock(db)
        yield db


def _device(db: Session, device_id: str) -> Device:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(404, "Device not found")
    return device


def _dev_dict(device: Device) -> dict:
    return {
        "device_id": device.device_id,
        "manufacturer": device.manufacturer,
        "model": device.model,
        "firmware_version": device.firmware_version,
        "support_until": device.support_until,
        "security": device.security,
    }


def _evidence_dict(item: EvidenceObservation) -> dict:
    return {
        "id": item.id,
        "device_id": item.device_id,
        "source_type": item.source_type,
        "attribute": item.attribute,
        "value": item.value,
        "observed_at": (
            item.observed_at.replace(tzinfo=timezone.utc)
            if item.observed_at.tzinfo is None
            else item.observed_at.astimezone(timezone.utc)
        ),
        "recorded_at": (
            item.recorded_at.replace(tzinfo=timezone.utc)
            if item.recorded_at.tzinfo is None
            else item.recorded_at.astimezone(timezone.utc)
        ),
        "confidence": item.confidence,
        "verification_status": item.verification_status,
        "evidence_reference": item.evidence_reference,
        "evidence_hash": item.evidence_hash,
    }


def _normalized_evidence_dict(item: EvidenceObservation) -> dict:
    raw = _evidence_dict(item)
    normalized = normalize_observation(item.attribute, item.value)
    return {
        **raw,
        "source_attribute": normalized.source_attribute,
        "canonical_attribute": normalized.canonical_attribute,
        "normalized_value": normalized.normalized_value,
        "normalizer_version": normalized.normalizer_version,
        "normalization_error": normalized.error,
    }


def _vuln_dict(vulnerability: Vulnerability) -> dict:
    return {column.name: getattr(vulnerability, column.name) for column in Vulnerability.__table__.columns}


def _vulns(db: Session, device_id: str) -> list[dict]:
    rows = db.scalars(select(Vulnerability).where(Vulnerability.device_id == device_id)).all()
    return sorted(
        (_vuln_dict(item) for item in rows),
        key=lambda item: (item["status"] in ("fixed", "not_affected"), SEV.get(item["severity"], 4)),
    )


async def _read_sbom_document(request: Request) -> dict:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_SBOM_BYTES:
            raise HTTPException(413, "SBOM request exceeds the 2 MiB limit")
        body.extend(chunk)
    try:
        document = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(422, "Request body must contain valid UTF-8 JSON") from None
    if not isinstance(document, dict):
        raise HTTPException(422, "SBOM document must be a JSON object")
    return document


@app.post("/products", status_code=201)
def create_product(body: ProductIn, db: Session = Depends(get_write_db), actor: str = Depends(auth)):
    product = product_sbom.create_product(db, actor, body.manufacturer, body.product_name, body.external_reference)
    return {"id": product.id, "manufacturer": product.manufacturer, "product_name": product.product_name,
            "external_reference": product.external_reference, "created_at": product.created_at}


@app.post("/products/{product_id}/releases", status_code=201)
def create_product_release(product_id: int, body: ProductReleaseIn, db: Session = Depends(get_write_db), actor: str = Depends(auth)):
    try:
        release = product_sbom.create_release(db, actor, product_id, body.version, body.hardware_revision, body.release_reference)
    except LookupError:
        raise HTTPException(404, "Product not found") from None
    return {"id": release.id, "product_id": release.product_id, "version": release.version,
            "hardware_revision": release.hardware_revision, "release_reference": release.release_reference,
            "created_at": release.created_at}


@app.post("/product-releases/{release_id}/sbom", status_code=201)
async def import_product_sbom(
    release_id: int, request: Request,
    source_type: str = Query(default="manual", pattern="^(manual|pipeline)$"),
    source_reference: str | None = Query(default=None, max_length=500),
    db: Session = Depends(get_db), actor: str = Depends(auth),
):
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > MAX_SBOM_BYTES:
            raise HTTPException(413, "SBOM request exceeds the 2 MiB limit")
        raw.extend(chunk)
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(422, "Request body must contain valid UTF-8 JSON") from None
    if not isinstance(document, dict):
        raise HTTPException(422, "SBOM document must be a JSON object")

    try:
        imported, created, metadata_reprocessed = await product_sbom.import_cyclonedx(
            db, actor, release_id, bytes(raw), document, source_type, source_reference
        )
    except LookupError:
        raise HTTPException(404, "Product release not found") from None
    except ValueError as error:
        raise HTTPException(422, str(error)) from None
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "SBOM import conflicts with an existing database record") from None
    return {"id": imported.id, "product_release_id": imported.product_release_id, "format": imported.format,
            "spec_version": imported.spec_version, "content_sha256": imported.content_sha256,
            "status": imported.status, "component_count": imported.component_count,
            "validation_summary": imported.validation_summary, "bom_metadata": imported.bom_metadata,
            "created": created, "metadata_reprocessed": metadata_reprocessed}


@app.get("/product-releases/{release_id}/sbom")
def list_product_sbom_imports(release_id: int, db: Session = Depends(get_db), _: str = Depends(auth)):
    if db.get(ProductRelease, release_id) is None:
        raise HTTPException(404, "Product release not found")
    imports = db.scalars(select(SBOMImport).where(SBOMImport.product_release_id == release_id)
                         .order_by(SBOMImport.imported_at, SBOMImport.id)).all()
    return [{"id": item.id, "format": item.format, "spec_version": item.spec_version,
             "content_sha256": item.content_sha256, "imported_at": item.imported_at,
             "component_count": item.component_count, "status": item.status,
             "validation_summary": item.validation_summary, "bom_metadata": item.bom_metadata}
            for item in imports]


@app.get("/product-releases/{release_id}/sbom/diff")
def compare_product_sbom_imports(
    release_id: int,
    from_import_id: int = Query(gt=0),
    to_import_id: int = Query(gt=0),
    db: Session = Depends(get_db),
    _: str = Depends(auth),
):
    try:
        return product_sbom.compare_imports(
            db, release_id, from_import_id, to_import_id
        )
    except LookupError as error:
        raise HTTPException(404, str(error)) from None


@app.post("/sbom/imports/{import_id}/assessments")
async def reassess_product_sbom(
    import_id: int,
    response: Response,
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    db: Session = Depends(get_db),
    actor: str = Depends(auth),
):
    try:
        assessment, created = await product_sbom.reassess_import(
            db, actor, import_id, idempotency_key
        )
    except LookupError as error:
        raise HTTPException(404, str(error)) from None
    except ValueError as error:
        raise HTTPException(409, str(error)) from None
    response.status_code = 201 if created else 200
    return {**assessment, "created": created}


@app.get("/sbom/imports/{import_id}/assessments")
def list_product_sbom_assessments(
    import_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(auth),
):
    try:
        return product_sbom.list_assessments(db, import_id)
    except LookupError as error:
        raise HTTPException(404, str(error)) from None


@app.get("/sbom/imports/{import_id}/assessments/{assessment_id}/findings")
def list_product_sbom_assessment_findings(
    import_id: int,
    assessment_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(auth),
):
    try:
        return product_sbom.list_assessment_findings(
            db, import_id, assessment_id
        )
    except LookupError as error:
        raise HTTPException(404, str(error)) from None


@app.post("/sbom/assessment-findings/{finding_id}/decisions", status_code=201)
def create_vulnerability_decision(
    finding_id: int,
    body: VulnerabilityDecisionIn,
    response: Response,
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    db: Session = Depends(get_write_db),
    actor: str = Depends(auth),
):
    if not actor.startswith("principal:"):
        raise HTTPException(
            403,
            "Human review decisions require a managed operator principal",
        )
    principal_id = actor.removeprefix("principal:")
    try:
        decision, created = vulnerability_decisions.create_decision(
            db,
            finding_id=finding_id,
            principal_id=principal_id,
            idempotency_key=idempotency_key,
            **body.model_dump(),
        )
        db.commit()
        response.status_code = 201 if created else 200
        return decision
    except LookupError as error:
        db.rollback()
        raise HTTPException(404, str(error)) from None
    except PermissionError as error:
        db.rollback()
        raise HTTPException(403, str(error)) from None
    except vulnerability_decisions.IdempotencyConflict as error:
        db.rollback()
        raise HTTPException(409, str(error)) from None
    except ValueError as error:
        db.rollback()
        raise HTTPException(422, str(error)) from None
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Decision revision conflicts with existing history") from None


@app.get("/sbom/assessment-findings/{finding_id}/decisions")
def list_vulnerability_decisions(
    finding_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(auth),
):
    try:
        return vulnerability_decisions.list_decisions(db, finding_id)
    except LookupError as error:
        raise HTTPException(404, str(error)) from None


@app.get("/sbom/imports/{import_id}/components")
def list_sbom_components(import_id: int, db: Session = Depends(get_db), _: str = Depends(auth)):
    if db.get(SBOMImport, import_id) is None:
        raise HTTPException(404, "SBOM import not found")
    rows = db.scalars(select(SBOMComponent).where(SBOMComponent.sbom_import_id == import_id)
                      .order_by(SBOMComponent.ordinal)).all()
    return [
        {
            "id": row.id,
            "ordinal": row.ordinal,
            "name": row.name,
            "version": row.version,
            "purl": row.purl,
            "bom_ref": row.bom_ref,
        }
        for row in rows
    ]


@app.get("/sbom/components/{component_id}/findings")
def list_product_findings(component_id: int, db: Session = Depends(get_db), _: str = Depends(auth)):
    if db.get(SBOMComponent, component_id) is None:
        raise HTTPException(404, "SBOM component not found")
    rows = db.scalars(select(ProductFinding).where(ProductFinding.sbom_component_id == component_id)
                      .order_by(ProductFinding.vuln_id, ProductFinding.source)).all()
    return [{"id": row.id, "vuln_id": row.vuln_id, "severity": row.severity, "fixed_in": row.fixed_in,
             "source": row.source, "status": row.status, "justification": row.justification} for row in rows]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/evidence", status_code=201)
def record_evidence(
    body: EvidenceObservationIn,
    db: Session = Depends(get_write_db),
    actor: str = Depends(auth),
):
    if body.device_id is not None:
        _device(db, body.device_id)
    observation = EvidenceObservation(
        **body.model_dump(),
        verification_status="unverified",
    )
    db.add(observation)
    db.flush()
    audit.record(
        db,
        actor,
        "evidence.record",
        body.device_id or "unassigned",
        {
            "observation_id": observation.id,
            "source_type": body.source_type,
            "attribute": body.attribute,
            "confidence": body.confidence,
            "evidence_hash": body.evidence_hash,
        },
    )
    db.commit()
    db.refresh(observation)
    return _evidence_dict(observation)


@app.get("/evidence")
def list_evidence(
    device_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: str = Depends(auth),
):
    statement = select(EvidenceObservation)
    if device_id is not None:
        _device(db, device_id)
        statement = statement.where(EvidenceObservation.device_id == device_id)
    rows = db.scalars(
        statement.order_by(EvidenceObservation.recorded_at, EvidenceObservation.id)
        .offset(offset)
        .limit(limit)
    ).all()
    return [_evidence_dict(item) for item in rows]


@app.get("/evidence/normalized")
def list_normalized_evidence(
    device_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: str = Depends(auth),
):
    statement = select(EvidenceObservation)
    if device_id is not None:
        _device(db, device_id)
        statement = statement.where(EvidenceObservation.device_id == device_id)
    rows = db.scalars(
        statement.order_by(EvidenceObservation.recorded_at, EvidenceObservation.id)
        .offset(offset)
        .limit(limit)
    ).all()
    return {
        "normalizer_version": NORMALIZER_VERSION,
        "items": [_normalized_evidence_dict(item) for item in rows],
    }


@app.post("/devices", status_code=201)
def create_device(body: DeviceIn, db: Session = Depends(get_write_db), actor: str = Depends(auth)):
    device = Device(
        device_id=body.device_id,
        manufacturer=body.manufacturer,
        model=body.model,
        firmware_version=body.firmware_version,
        support_until=body.support_until,
        security=body.security.model_dump(),
    )
    db.add(device)
    try:
        audit.record(db, actor, "device.create", device.device_id, body.model_dump(mode="json"))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Device already exists") from None
    return _dev_dict(device)


@app.get("/devices")
def list_devices(db: Session = Depends(get_db), _: str = Depends(auth)):
    return [_dev_dict(device) for device in db.scalars(select(Device).order_by(Device.device_id))]


@app.get("/devices/{device_id}")
def get_device(device_id: str, db: Session = Depends(get_db), _: str = Depends(auth)):
    return _dev_dict(_device(db, device_id))


@app.put("/devices/{device_id}/security")
def update_security(
    device_id: str,
    body: SecurityProfile,
    db: Session = Depends(get_write_db),
    actor: str = Depends(auth),
):
    device = _device(db, device_id)
    old_security = device.security
    device.security = body.model_dump()
    audit.record(
        db,
        actor,
        "device.security_update",
        device_id,
        {"old": old_security, "new": device.security},
    )
    db.commit()
    return _dev_dict(device)


@app.get("/devices/{device_id}/posture")
def get_posture(device_id: str, db: Session = Depends(get_db), _: str = Depends(auth)):
    return posture.assess(_dev_dict(_device(db, device_id)))


@app.post("/devices/{device_id}/sbom")
async def import_sbom(
    device_id: str,
    request: Request,
    db: Session = Depends(get_db),
    actor: str = Depends(auth),
):
    document = await _read_sbom_document(request)
    try:
        components = sbom.parse_cyclonedx(document)
    except ValueError as error:
        raise HTTPException(422, str(error)) from None

    scan_results = sbom.scan(components)
    audit.acquire_chain_lock(db)
    _device(db, device_id)

    new_findings = 0
    for finding in scan_results:
        existing = db.scalars(
            select(Vulnerability).where(
                Vulnerability.device_id == device_id,
                Vulnerability.component == finding["component"],
                Vulnerability.version == finding["version"],
                Vulnerability.vuln_id == finding["vuln_id"],
            )
        ).first()
        if not existing:
            db.add(Vulnerability(device_id=device_id, **finding))
            new_findings += 1

    audit.record(
        db,
        actor,
        "sbom.import",
        device_id,
        {"components": len(components), "new_findings": new_findings},
    )
    db.commit()
    return {"components": len(components), "new_findings": new_findings}


@app.get("/devices/{device_id}/vulnerabilities")
def list_vulnerabilities(device_id: str, db: Session = Depends(get_db), _: str = Depends(auth)):
    _device(db, device_id)
    return _vulns(db, device_id)


@app.patch("/vulnerabilities/{vuln_pk}")
def triage(
    vuln_pk: int,
    body: TriageIn,
    db: Session = Depends(get_write_db),
    actor: str = Depends(auth),
):
    vulnerability = db.get(Vulnerability, vuln_pk)
    if not vulnerability:
        raise HTTPException(404, "Vulnerability not found")
    old_status = vulnerability.status
    vulnerability.status = body.status
    vulnerability.justification = body.justification
    audit.record(
        db,
        actor,
        "vulnerability.triage",
        f"{vulnerability.device_id}/{vulnerability.vuln_id}",
        {"from": old_status, "to": body.status, "justification": body.justification},
    )
    db.commit()
    return _vuln_dict(vulnerability)


@app.get("/devices/{device_id}/report")
def report(
    device_id: str,
    format: str = "json",
    db: Session = Depends(get_db),
    _: str = Depends(auth),
):
    device = _device(db, device_id)
    assessment = posture.assess(_dev_dict(device))
    vulnerabilities = _vulns(db, device_id)
    trail = [
        {"ts": entry.ts, "action": entry.action, "payload": entry.payload}
        for entry in db.scalars(
            select(AuditEntry)
            .where(
                or_(
                    AuditEntry.entity == device_id,
                    AuditEntry.entity.startswith(f"{device_id}/", autoescape=True),
                )
            )
            .order_by(AuditEntry.id)
        )
    ]
    if format == "json":
        return {
            "device": _dev_dict(device),
            "posture": assessment,
            "vulnerabilities": vulnerabilities,
            "evidence_trail": trail,
        }

    lines = [
        f"# Security report: {device.device_id}",
        f"{device.manufacturer} {device.model} (fw {device.firmware_version})",
        "",
        f"Highest risk: **{assessment['highest_risk']}** | Evidence coverage: {assessment['evidence_coverage']}",
        "",
        "## Controls",
    ]
    lines += [
        f"- **{control['control']}**: {control['status']} ({control['risk']}) - "
        f"{control['justification']} Action: {control['recommendation']}"
        for control in assessment["controls"]
    ]
    lines += ["", "## Vulnerabilities"] + [
        f"- {item['vuln_id']} {item['component']} {item['version']} "
        f"[{item['severity']}] status={item['status']}"
        for item in vulnerabilities
    ]
    lines += ["", f"_{assessment['disclaimer']}_"]
    return PlainTextResponse("\n".join(lines), media_type="text/markdown")


@app.get("/audit")
def get_audit(db: Session = Depends(get_db), _: str = Depends(auth)):
    return [
        {
            "id": entry.id,
            "ts": entry.ts,
            "actor": entry.actor,
            "action": entry.action,
            "entity": entry.entity,
            "hash": entry.hash,
        }
        for entry in db.scalars(select(AuditEntry).order_by(AuditEntry.id))
    ]


@app.get("/audit/verify")
def verify_audit(db: Session = Depends(get_db), _: str = Depends(auth)):
    return audit.verify(db)
