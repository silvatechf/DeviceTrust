import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from time import sleep
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, update
from sqlalchemy.orm import Session

from app import audit, product_sbom
from app.db import (
    AuditChainState,
    AuditEntry,
    Base,
    Product,
    ProductFinding,
    SBOMComponent,
    SBOMImport,
    SessionLocal,
)
from app.main import app, get_write_db
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


def _isolated_api_database(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'api-audit-atomicity.db'}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(AuditChainState(id=1, version=0))
        db.commit()
    return engine


def _write_database_override(engine):
    def override_write_db():
        with Session(engine) as db:
            audit.acquire_chain_lock(db)
            yield db

    return override_write_db


def test_concurrent_product_api_writes_keep_domain_and_audit_atomic(
    tmp_path, monkeypatch
):
    engine = _isolated_api_database(tmp_path)
    monkeypatch.setitem(
        app.dependency_overrides,
        get_write_db,
        _write_database_override(engine),
    )
    writer_count = 8
    barrier = Barrier(writer_count)
    original_digest = audit._digest

    def slow_digest(prev, ts, actor, action, entity, payload):
        sleep(0.02)
        return original_digest(prev, ts, actor, action, entity, payload)

    monkeypatch.setattr(audit, "_digest", slow_digest)

    try:
        with Session(engine) as db:
            version_before = db.get(AuditChainState, 1).version

        def create_product(index):
            with TestClient(app) as api:
                barrier.wait(timeout=10)
                return api.post(
                    "/products",
                    json={
                        "manufacturer": "Concurrent API Test",
                        "product_name": f"concurrent-{uuid4().hex}-{index}",
                    },
                    headers=H,
                )

        with ThreadPoolExecutor(max_workers=writer_count) as executor:
            responses = list(executor.map(create_product, range(writer_count)))

        assert all(response.status_code == 201 for response in responses)
        product_ids = {response.json()["id"] for response in responses}
        assert len(product_ids) == writer_count

        with Session(engine) as db:
            products = db.query(Product).filter(Product.id.in_(product_ids)).all()
            entries = (
                db.query(AuditEntry)
                .filter(
                    AuditEntry.actor == "api-key",
                    AuditEntry.action == "product.create",
                    AuditEntry.entity.in_(
                        [str(product_id) for product_id in product_ids]
                    ),
                )
                .all()
            )
            state = db.get(AuditChainState, 1)
            assert state is not None
            assert {product.id for product in products} == product_ids
            assert {entry.entity for entry in entries} == {
                str(product_id) for product_id in product_ids
            }
            assert len(entries) == writer_count
            assert state.version == version_before + writer_count
            assert audit.verify(db) == {"valid": True, "entries": writer_count}
    finally:
        engine.dispose()


def test_failed_product_api_write_rolls_back_domain_audit_and_releases_lock(
    tmp_path, monkeypatch
):
    engine = _isolated_api_database(tmp_path)
    monkeypatch.setitem(
        app.dependency_overrides,
        get_write_db,
        _write_database_override(engine),
    )
    product_name = f"rollback-{uuid4().hex}"
    original_record = audit.record

    try:
        with Session(engine) as db:
            state = db.get(AuditChainState, 1)
            assert state is not None
            version_before = state.version
            audit_count_before = db.query(AuditEntry).count()

        def fail_after_audit_flush(db, actor, action, entity, payload):
            original_record(db, actor, action, entity, payload)
            raise RuntimeError("injected failure after audit flush")

        monkeypatch.setattr(audit, "record", fail_after_audit_flush)
        with TestClient(app, raise_server_exceptions=False) as api:
            failed = api.post(
                "/products",
                json={"manufacturer": "Rollback Test", "product_name": product_name},
                headers=H,
            )
            assert failed.status_code == 500

            monkeypatch.setattr(audit, "record", original_record)
            with Session(engine) as db:
                state = db.get(AuditChainState, 1)
                assert state is not None
                assert state.version == version_before
                assert db.query(Product).filter_by(product_name=product_name).count() == 0
                assert db.query(AuditEntry).count() == audit_count_before

            recovered = api.post(
                "/products",
                json={"manufacturer": "Rollback Test", "product_name": product_name},
                headers=H,
            )
            assert recovered.status_code == 201

        with Session(engine) as db:
            state = db.get(AuditChainState, 1)
            assert state is not None
            assert state.version == version_before + 1
            assert db.query(Product).filter_by(product_name=product_name).count() == 1
            assert (
                db.query(AuditEntry)
                .filter(
                    AuditEntry.action == "product.create",
                    AuditEntry.entity == str(recovered.json()["id"]),
                )
                .count()
                == 1
            )
            assert audit.verify(db) == {"valid": True, "entries": 1}
    finally:
        engine.dispose()
def _create_product_release(client, product_name: str) -> int:
    product = client.post(
        "/products",
        json={"manufacturer": "Example Vendor", "product_name": product_name},
        headers=H,
    )
    assert product.status_code == 201
    release = client.post(
        f"/products/{product.json()['id']}/releases",
        json={"version": "1.0.0"},
        headers=H,
    )
    assert release.status_code == 201
    return release.json()["id"]


def test_product_sbom_changed_content_creates_new_import_and_hashes_exact_bytes(client):
    release_id = _create_product_release(client, "Digest Change Test")
    raw = (Path(__file__).parent.parent / "samples" / "sensor_sbom.json").read_bytes()
    changed_raw = raw + b"\n"

    first = client.post(
        f"/product-releases/{release_id}/sbom",
        content=raw,
        headers={**H, "Content-Type": "application/json"},
    )
    second = client.post(
        f"/product-releases/{release_id}/sbom",
        content=changed_raw,
        headers={**H, "Content-Type": "application/json"},
    )

    assert first.status_code == second.status_code == 201
    first_body = first.json()
    second_body = second.json()
    assert first_body["created"] is True
    assert second_body["created"] is True
    assert first_body["id"] != second_body["id"]
    assert first_body["content_sha256"] == hashlib.sha256(raw).hexdigest()
    assert second_body["content_sha256"] == hashlib.sha256(changed_raw).hexdigest()

    imports = client.get(f"/product-releases/{release_id}/sbom", headers=H)
    assert imports.status_code == 200
    assert {item["id"] for item in imports.json()} == {
        first_body["id"],
        second_body["id"],
    }


def test_identical_sbom_bytes_are_distinct_across_product_releases(client):
    product = client.post(
        "/products",
        json={"manufacturer": "Example Vendor", "product_name": "Release Boundary Test"},
        headers=H,
    )
    assert product.status_code == 201
    product_id = product.json()["id"]

    release_ids = []
    for version in ("1.0.0", "1.0.1"):
        release = client.post(
            f"/products/{product_id}/releases",
            json={"version": version},
            headers=H,
        )
        assert release.status_code == 201
        release_ids.append(release.json()["id"])

    raw = (Path(__file__).parent.parent / "samples" / "sensor_sbom.json").read_bytes()
    imports = []
    for release_id in release_ids:
        response = client.post(
            f"/product-releases/{release_id}/sbom",
            content=raw,
            headers={**H, "Content-Type": "application/json"},
        )
        assert response.status_code == 201
        assert response.json()["created"] is True
        imports.append(response.json())

    assert imports[0]["id"] != imports[1]["id"]
    assert imports[0]["content_sha256"] == imports[1]["content_sha256"]
    for release_id, imported in zip(release_ids, imports, strict=True):
        listed = client.get(f"/product-releases/{release_id}/sbom", headers=H)
        assert [item["id"] for item in listed.json()] == [imported["id"]]


def test_product_sbom_import_rolls_back_all_rows_when_audit_append_fails(client, monkeypatch):
    release_id = _create_product_release(client, "Atomic Rollback Test")
    raw = (Path(__file__).parent.parent / "samples" / "sensor_sbom.json").read_bytes()

    with SessionLocal() as db:
        audit_count_before = db.query(AuditEntry).filter_by(
            action="sbom.product_import"
        ).count()

    original_record = product_sbom.audit.record

    def fail_import_audit(db, actor, action, entity, payload):
        result = original_record(db, actor, action, entity, payload)
        if action == "sbom.product_import":
            raise RuntimeError("injected audit append failure")
        return result

    monkeypatch.setattr(product_sbom.audit, "record", fail_import_audit)

    with pytest.raises(RuntimeError, match="injected audit append failure"):
        client.post(
            f"/product-releases/{release_id}/sbom",
            content=raw,
            headers={**H, "Content-Type": "application/json"},
        )

    with SessionLocal() as db:
        assert db.query(SBOMImport).filter_by(product_release_id=release_id).count() == 0
        assert (
            db.query(SBOMComponent)
            .join(SBOMImport)
            .filter(SBOMImport.product_release_id == release_id)
            .count()
            == 0
        )
        assert (
            db.query(ProductFinding)
            .join(SBOMComponent)
            .join(SBOMImport)
            .filter(SBOMImport.product_release_id == release_id)
            .count()
            == 0
        )
        assert (
            db.query(AuditEntry).filter_by(action="sbom.product_import").count()
            == audit_count_before
        )
