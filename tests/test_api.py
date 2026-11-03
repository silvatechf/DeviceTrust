import json
from pathlib import Path

from sqlalchemy import update

from app.db import AuditEntry, SessionLocal
from app.seed import DEVICES

from .conftest import H

SBOM = json.loads((Path(__file__).parent.parent / "samples" / "sensor_sbom.json").read_text())


def test_auth_required(client):
    assert client.get("/devices").status_code == 401
    assert client.get("/devices", headers={"X-API-Key": "bad"}).status_code == 401
    assert client.get("/health").status_code == 200


def test_device_lifecycle_and_validation(client):
    assert client.post("/devices", json=DEVICES[0], headers=H).status_code == 201
    assert client.post("/devices", json=DEVICES[0], headers=H).status_code == 409
    bad = {**DEVICES[1], "device_id": "../etc"}
    assert client.post("/devices", json=bad, headers=H).status_code == 422
    extra = {**DEVICES[1], "hack": 1}
    assert client.post("/devices", json=extra, headers=H).status_code == 422


def test_posture_is_evidence_based(client):
    client.post("/devices", json=DEVICES[1], headers=H)
    p = client.get("/devices/CAM-002/posture", headers=H).json()
    assert p["highest_risk"] == "high" and len(p["controls"]) == 8
    assert all(c["evidence"] and c["justification"] for c in p["controls"])
    assert {c["control"]: c["status"] for c in p["controls"]}["secure_software_update"] == "non_compliant"


def test_unknown_is_not_compliant(client):
    p = client.get("/devices/TEMP-001/posture", headers=H).json()
    statuses = {item["control"]: item["status"] for item in p["controls"]}
    assert statuses["security_state_awareness"] == "unverified"
    assert statuses["device_integrity"] == "unverified"
    assert statuses["network_exposure"] == "unverified"
    assert p["evidence_coverage"] == "5/8"


def test_sbom_scan_and_triage(client):
    response = client.post("/devices/CAM-002/sbom", json=SBOM, headers=H).json()
    assert response["components"] == 3 and response["new_findings"] == 2
    assert client.post("/devices/CAM-002/sbom", json=SBOM, headers=H).json()["new_findings"] == 0
    vulnerabilities = client.get("/devices/CAM-002/vulnerabilities", headers=H).json()
    assert vulnerabilities[0]["severity"] == "critical"
    short = client.patch(
        f"/vulnerabilities/{vulnerabilities[0]['id']}",
        json={"status": "fixed", "justification": "x"},
        headers=H,
    )
    assert short.status_code == 422
    accepted = client.patch(
        f"/vulnerabilities/{vulnerabilities[0]['id']}",
        json={"status": "accepted_risk", "justification": "Isolated VLAN, patch in Q1"},
        headers=H,
    )
    assert accepted.json()["status"] == "accepted_risk"


def test_invalid_sbom_rejected(client):
    assert client.post("/devices/CAM-002/sbom", json={"foo": 1}, headers=H).status_code == 422


def test_report_markdown(client):
    response = client.get("/devices/CAM-002/report?format=md", headers=H)
    assert response.status_code == 200 and "Highest risk" in response.text


def test_audit_chain_detects_tampering(client):
    assert client.get("/audit/verify", headers=H).json()["valid"] is True
    with SessionLocal() as db:
        db.execute(update(AuditEntry).where(AuditEntry.id == 1).values(actor="attacker"))
        db.commit()
    assert client.get("/audit/verify", headers=H).json()["valid"] is False


def test_internet_exposed_management_is_high_risk_even_with_authentication(client):
    device = {
        "device_id": "EDGE-004",
        "manufacturer": "Example IoT",
        "model": "Edge Controller",
        "firmware_version": "2.1.0",
        "security": {
            "internet_exposed": False,
            "management_interfaces": [
                {
                    "name": "web-admin",
                    "protocol": "https",
                    "internet_exposed": True,
                    "authentication_required": True,
                }
            ],
        },
    }
    assert client.post("/devices", json=device, headers=H).status_code == 201
    posture = client.get("/devices/EDGE-004/posture", headers=H).json()
    exposure = next(item for item in posture["controls"] if item["control"] == "network_exposure")
    assert exposure["risk"] == "high"
    assert exposure["status"] == "non_compliant"
    assert exposure["evidence"]["internet_exposed"] is False


def test_unknown_exposure_is_not_assumed_safe(client):
    device = {
        "device_id": "EDGE-005",
        "manufacturer": "Example IoT",
        "model": "Unknown Edge",
        "firmware_version": "1.0.0",
        "security": {},
    }
    assert client.post("/devices", json=device, headers=H).status_code == 201
    posture = client.get("/devices/EDGE-005/posture", headers=H).json()
    exposure = next(item for item in posture["controls"] if item["control"] == "network_exposure")
    assert exposure["status"] == "unverified"
    assert exposure["risk"] == "unknown"
