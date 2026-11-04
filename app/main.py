import hmac
import json
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import audit, posture, sbom
from .db import AuditEntry, Device, SessionLocal, Vulnerability, init_db
from .schemas import DeviceIn, SecurityProfile, TriageIn

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
MAX_SBOM_BYTES = 2 * 1024 * 1024


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="DeviceTrust", version="0.2.0", lifespan=lifespan)


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
