import hmac
import json
import os
from datetime import timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import audit, posture, sbom
from .db import AuditEntry, Device, EvidenceObservation, SessionLocal, Vulnerability
from .evidence_normalization import NORMALIZER_VERSION, normalize_observation
from .schemas import DeviceIn, EvidenceObservationIn, SecurityProfile, TriageIn

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


def auth(x_api_key: str = Header(default="")) -> str:
    expected = os.getenv("DEVICETRUST_API_KEY")
    if not expected:
        raise HTTPException(503, "API key not configured")
    if not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(401, "Invalid API key")
    return "api-key"


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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/evidence", status_code=201)
def record_evidence(
    body: EvidenceObservationIn,
    db: Session = Depends(get_db),
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
def create_device(body: DeviceIn, db: Session = Depends(get_db), actor: str = Depends(auth)):
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
    db: Session = Depends(get_db),
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
    _device(db, device_id)
    document = await _read_sbom_document(request)
    try:
        components = sbom.parse_cyclonedx(document)
    except ValueError as error:
        raise HTTPException(422, str(error)) from None

    new_findings = 0
    for finding in sbom.scan(components):
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
    db: Session = Depends(get_db),
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
