import json
from pathlib import Path

from sqlalchemy import update

from app.db import AuditChainState, AuditEntry, SessionLocal
from app.seed import DEVICES

from .conftest import H

SBOM = json.loads((Path(__file__).parent.parent / "samples" / "sensor_sbom.json").read_text())


def test_auth_required(client):
    assert client.get("/devices").status_code == 401
    assert client.get("/devices", headers={"X-API-Key": "bad"}).status_code == 401
    assert client.get("/health").status_code == 200
    assert client.get("/evidence").status_code == 401
    assert client.get("/evidence/normalized").status_code == 401


def test_evidence_observation_lifecycle(client):
    device = {
        "device_id": "EVIDENCE-001",
        "manufacturer": "Example IoT",
        "model": "Gateway",
        "firmware_version": "1.0.0",
    }
    assert client.post("/devices", json=device, headers=H).status_code == 201
    payload = {
        "device_id": "EVIDENCE-001",
        "source_type": "router_import",
        "attribute": "firmware_version",
        "value": "2.4.1",
        "confidence": "medium",
        "evidence_reference": "router-export:devices.csv#row-8",
    }
    created = client.post("/evidence", json=payload, headers=H)
    assert created.status_code == 201
    observation = created.json()
    assert observation["verification_status"] == "unverified"
    assert observation["confidence"] == "medium"
    assert observation["device_id"] == "EVIDENCE-001"
    assert observation["recorded_at"].endswith("+00:00")
    assert observation["observed_at"].endswith("+00:00")
    assert isinstance(observation["id"], int)
    assert len(client.get("/evidence?device_id=EVIDENCE-001", headers=H).json()) == 1
    assert client.get("/evidence?device_id=TEMP-UNKNOWN", headers=H).status_code == 404
    audit = client.get("/audit", headers=H).json()
    assert any(item["action"] == "evidence.record" for item in audit)


def test_unassigned_evidence_and_input_boundaries(client):
    payload = {
        "source_type": "manual",
        "attribute": "manufacturer",
        "value": "Unknown vendor",
    }
    created = client.post("/evidence", json=payload, headers=H)
    assert created.status_code == 201
    assert created.json()["device_id"] is None
    assert created.json()["verification_status"] == "unverified"

    invalid_hash = {**payload, "evidence_hash": "not-a-sha256"}
    assert client.post("/evidence", json=invalid_hash, headers=H).status_code == 422
    unknown_source = {**payload, "source_type": "random_importer"}
    assert client.post("/evidence", json=unknown_source, headers=H).status_code == 422
    extra = {**payload, "verification_status": "verified"}
    assert client.post("/evidence", json=extra, headers=H).status_code == 422
    oversized_value = {**payload, "value": "x" * 1001}
    assert client.post("/evidence", json=oversized_value, headers=H).status_code == 422
    naive_timestamp = {**payload, "observed_at": "2026-11-04T10:30:00"}
    assert client.post("/evidence", json=naive_timestamp, headers=H).status_code == 422


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


def test_api_fails_closed_when_server_key_is_unset(client, monkeypatch):
    monkeypatch.delenv("DEVICETRUST_API_KEY")
    response = client.get("/devices", headers=H)
    assert response.status_code == 503


def test_audit_chain_cannot_detect_deleted_tail_without_checkpoint(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app.audit import record, verify
    from app.db import AuditChainState, Base

    engine = create_engine(f"sqlite:///{tmp_path / 'audit-tail.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(AuditChainState(id=1, version=0))
        db.commit()
        record(db, "test", "device.create", "DEVICE-1", {"id": 1})
        db.commit()
        record(db, "test", "device.update", "DEVICE-1", {"id": 1})
        db.commit()
        last = db.query(AuditEntry).order_by(AuditEntry.id.desc()).first()
        assert last is not None
        db.delete(last)
        db.commit()
        # No external anchor exists to prove the final entry was deleted.
        assert verify(db)["valid"] is True
    engine.dispose()



def test_evidence_listing_is_paginated_and_bounded(client):
    device_id = "PAGINATION-001"

    device = {
        "device_id": device_id,
        "manufacturer": "Example IoT",
        "model": "Pagination Gateway",
        "firmware_version": "1.0.0",
    }
    created_device = client.post("/devices", json=device, headers=H)
    assert created_device.status_code == 201

    for index in range(3):
        response = client.post(
            "/evidence",
            json={
                "device_id": device_id,
                "source_type": "manual",
                "attribute": "inventory_note",
                "value": f"observation-{index}",
            },
            headers=H,
        )
        assert response.status_code == 201

    endpoint = f"/evidence?device_id={device_id}"

    first_page = client.get(f"{endpoint}&limit=2&offset=0", headers=H)
    second_page = client.get(f"{endpoint}&limit=2&offset=2", headers=H)

    assert first_page.status_code == 200
    assert second_page.status_code == 200
    assert len(first_page.json()) == 2
    assert len(second_page.json()) == 1

    assert first_page.json()[0]["id"] < first_page.json()[1]["id"]
    assert first_page.json()[1]["id"] < second_page.json()[0]["id"]

    assert client.get("/evidence?limit=201", headers=H).status_code == 422
    assert client.get("/evidence?limit=0", headers=H).status_code == 422
    assert client.get("/evidence?offset=-1", headers=H).status_code == 422


def test_normalized_evidence_projection_preserves_raw_and_unknown_values(client):
    payloads = [
        {"source_type": "network_observation", "attribute": "mac_address", "value": "AA-BB-CC-DD-EE-FF"},
        {"source_type": "network_observation", "attribute": "ip_address", "value": "192.0.2.10"},
        {"source_type": "manual", "attribute": "vendor.custom_field", "value": "unclassified"},
        {"source_type": "manual", "attribute": "secure_boot", "value": "maybe"},
    ]
    for payload in payloads:
        assert client.post("/evidence", json=payload, headers=H).status_code == 201

    response = client.get("/evidence/normalized?limit=10", headers=H)
    assert response.status_code == 200
    body = response.json()
    assert body["normalizer_version"] == "1.0.0"
    by_attribute = {item["attribute"]: item for item in body["items"]}

    mac = by_attribute["mac_address"]
    assert mac["value"] == "AA-BB-CC-DD-EE-FF"
    assert mac["canonical_attribute"] == "network.mac_address"
    assert mac["normalized_value"] == "aa:bb:cc:dd:ee:ff"
    assert mac["verification_status"] == "unverified"

    assert by_attribute["ip_address"]["normalized_value"] == "192.0.2.10"

    unknown = by_attribute["vendor.custom_field"]
    assert unknown["canonical_attribute"] is None
    assert unknown["normalized_value"] is None
    assert unknown["value"] == "unclassified"

    invalid = by_attribute["secure_boot"]
    assert invalid["canonical_attribute"] == "security.secure_boot"
    assert invalid["normalized_value"] is None
    assert invalid["normalization_error"] == "ambiguous boolean value"

    assert client.get("/evidence/normalized?limit=201", headers=H).status_code == 422
    assert client.get("/evidence/normalized?offset=-1", headers=H).status_code == 422


def test_product_sbom_import_is_persistent_and_idempotent(client):
    product_response = client.post(
        "/products",
        json={"manufacturer": "Example Vendor", "product_name": "Sensor X"},
        headers=H,
    )
    assert product_response.status_code == 201
    product_id = product_response.json()["id"]

    release_response = client.post(
        f"/products/{product_id}/releases",
        json={"version": "1.2.3", "hardware_revision": "rev-A"},
        headers=H,
    )
    assert release_response.status_code == 201
    release_id = release_response.json()["id"]

    raw_sbom = (Path(__file__).parent.parent / "samples" / "sensor_sbom.json").read_bytes()
    first = client.post(
        f"/product-releases/{release_id}/sbom",
        content=raw_sbom,
        headers={**H, "Content-Type": "application/json"},
    )
    assert first.status_code == 201
    first_body = first.json()
    assert first_body["created"] is True
    assert first_body["component_count"] == 3
    assert len(first_body["content_sha256"]) == 64

    retry = client.post(
        f"/product-releases/{release_id}/sbom",
        content=raw_sbom,
        headers={**H, "Content-Type": "application/json"},
    )
    assert retry.status_code == 201
    assert retry.json()["id"] == first_body["id"]
    assert retry.json()["created"] is False

    imports = client.get(f"/product-releases/{release_id}/sbom", headers=H)
    assert imports.status_code == 200
    assert len(imports.json()) == 1

    components = client.get(f"/sbom/imports/{first_body['id']}/components", headers=H)
    assert components.status_code == 200
    assert len(components.json()) == 3
    assert [item["ordinal"] for item in components.json()] == [0, 1, 2]

    vulnerable = next(item for item in components.json() if item["name"].lower() == "openssl")
    findings = client.get(f"/sbom/components/{vulnerable['id']}/findings", headers=H)
    assert findings.status_code == 200
    assert findings.json()


def test_product_sbom_import_rejects_invalid_document_without_persisting(client):
    product = client.post(
        "/products",
        json={"manufacturer": "Example Vendor", "product_name": "Invalid SBOM Target"},
        headers=H,
    ).json()
    release = client.post(
        f"/products/{product['id']}/releases",
        json={"version": "0.0.1"},
        headers=H,
    ).json()
    response = client.post(
        f"/product-releases/{release['id']}/sbom",
        json={"bomFormat": "CycloneDX", "components": []},
        headers=H,
    )
    assert response.status_code == 422
    imports = client.get(f"/product-releases/{release['id']}/sbom", headers=H)
    assert imports.status_code == 200
    assert imports.json() == []


def test_product_sbom_endpoints_require_authentication(client):
    assert client.post("/products", json={"manufacturer": "X", "product_name": "Y"}).status_code == 401
    assert client.post("/products/1/releases", json={"version": "1"}).status_code == 401
    assert client.get("/product-releases/1/sbom").status_code == 401


def test_product_sbom_findings_are_scoped_to_exact_component_occurrence(client):
    product = client.post(
        "/products",
        json={"manufacturer": "Example Vendor", "product_name": "Collision Test"},
        headers=H,
    )
    assert product.status_code == 201

    release = client.post(
        f"/products/{product.json()['id']}/releases",
        json={"version": "1.0.0"},
        headers=H,
    )
    assert release.status_code == 201
    release_id = release.json()["id"]

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "  OpenSSL  ",
                "version": "  1.1.1  ",
                "purl": "pkg:generic/openssl@1.1.1",
            },
            {
                "type": "library",
                "name": "openssl",
                "version": "1.1.1",
                "purl": "pkg:pypi/openssl@1.1.1",
            },
        ],
    }

    imported = client.post(
        f"/product-releases/{release_id}/sbom",
        json=document,
        headers=H,
    )
    assert imported.status_code == 201

    components = client.get(
        f"/sbom/imports/{imported.json()['id']}/components",
        headers=H,
    ).json()

    assert len(components) == 2

    generic_component = next(
        item for item in components
        if item["purl"] == "pkg:generic/openssl@1.1.1"
    )
    assert generic_component["name"] == "  OpenSSL  "
    assert generic_component["version"] == "  1.1.1  "

    findings = {
        component["purl"]: client.get(
            f"/sbom/components/{component['id']}/findings",
            headers=H,
        ).json()
        for component in components
    }

    assert [item["vuln_id"] for item in findings["pkg:generic/openssl@1.1.1"]] == [
        "DT-DEMO-0002"
    ]
    assert findings["pkg:pypi/openssl@1.1.1"] == []



def test_unauthenticated_write_does_not_acquire_audit_chain_lock(client):
    with SessionLocal() as db:
        state = db.get(AuditChainState, 1)
        assert state is not None
        version_before = state.version

    response = client.post(
        "/products",
        json={"manufacturer": "Unauthenticated", "product_name": "Must Not Persist"},
    )
    assert response.status_code == 401

    with SessionLocal() as db:
        state = db.get(AuditChainState, 1)
        assert state is not None
        assert state.version == version_before
