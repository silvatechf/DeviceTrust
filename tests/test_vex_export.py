import json

import pytest
from sqlalchemy import select

from app import audit, identity, vulnerability_decisions, vex_export
from app.db import (
    Product,
    ProductRelease,
    SBOMAssessment,
    SBOMAssessmentFinding,
    SBOMComponent,
    SBOMImport,
    SessionLocal,
)

from .conftest import H


def _release_with_import(*, metadata_component=True, serial_number=True):
    with SessionLocal() as db:
        product = Product(manufacturer="VEX Test Vendor", product_name="VEX Test Product")
        db.add(product)
        db.flush()
        release = ProductRelease(product_id=product.id, version="2.0.0")
        db.add(release)
        db.flush()
        metadata = {
            "serial_number": (
                "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
                if serial_number else None
            ),
            "version": 1,
            "metadata_component": (
                {
                    "bom_ref": "vex-test-product",
                    "type": "device",
                    "name": "VEX Test Product",
                    "version": "2.0.0",
                    "purl": None,
                }
                if metadata_component else None
            ),
        }
        imported = SBOMImport(
            product_release_id=release.id,
            format="CycloneDX",
            spec_version="1.5",
            source_type="manual",
            content_sha256="a" * 64,
            parser_version="0.4.0",
            status="accepted",
            component_count=1,
            validation_summary={"valid": True},
            bom_metadata=metadata,
        )
        db.add(imported)
        db.flush()
        component = SBOMComponent(
            sbom_import_id=imported.id,
            ordinal=0,
            name="openssl",
            version="3.0.0",
            purl="pkg:generic/openssl@3.0.0",
            bom_ref="openssl-3",
        )
        db.add(component)
        db.flush()
        assessment = SBOMAssessment(
            sbom_import_id=imported.id,
            request_key_hash="b" * 64,
            source_fingerprint="c" * 64,
            status="complete",
            component_count=1,
            finding_count=1,
            enrichment_metadata={},
        )
        db.add(assessment)
        db.flush()
        finding = SBOMAssessmentFinding(
            assessment_id=assessment.id,
            sbom_component_id=component.id,
            vuln_id="CVE-2026-12345",
            severity="high",
            fixed_in="3.0.1",
            source="osv",
            intelligence={},
            applicability={"status": "osv_reported_affected"},
        )
        db.add(finding)
        db.commit()
        return release.id, imported.id, assessment.id, finding.id


def _token(scopes):
    with SessionLocal() as db:
        principal, _credential, token = identity.create_principal(
            db,
            name="VEX export operator",
            kind="operator",
            scopes=set(scopes),
        )
        db.commit()
    return principal.id, token


def test_vex_export_is_deterministic_and_audited_for_empty_review_set(client, monkeypatch):
    release_id, import_id, assessment_id, _finding_id = _release_with_import()
    _principal_id, token = _token({"vex:export"})
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")
    url = f"/product-releases/{release_id}/sbom/{import_id}/vex"
    params = {"assessment_id": assessment_id}
    headers = {"X-API-Key": token}

    first = client.post(url, params=params, headers=headers)
    assert first.status_code == 200, first.text
    first_data = first.json()
    assert first_data["bom"]["bomFormat"] == "CycloneDX"
    assert first_data["bom"]["specVersion"] == "1.5"
    assert first_data["bom"]["vulnerabilities"] == []
    assert first_data["decision_count"] == 0
    assert first_data["vulnerability_count"] == 0

    second = client.post(url, params=params, headers=headers)
    assert second.status_code == 200, second.text
    assert second.json()["bom"] == first_data["bom"]
    assert second.json()["bom_sha256"] == first_data["bom_sha256"]

    with SessionLocal() as db:
        entries = db.scalars(
            select(audit.AuditEntry).where(
                audit.AuditEntry.action == "product_sbom.vex.export",
                audit.AuditEntry.entity == str(import_id),
            )
        ).all()
        assert len(entries) == 2


def test_vex_export_requires_dedicated_scope(client, monkeypatch):
    release_id, import_id, assessment_id, _finding_id = _release_with_import()
    _principal_id, token = _token({"assessment:read"})
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")

    response = client.post(
        f"/product-releases/{release_id}/sbom/{import_id}/vex",
        params={"assessment_id": assessment_id},
        headers={"X-API-Key": token},
    )
    assert response.status_code == 403


def test_vex_export_rejects_legacy_shared_key(client, monkeypatch):
    release_id, import_id, assessment_id, _finding_id = _release_with_import()
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "legacy")

    response = client.post(
        f"/product-releases/{release_id}/sbom/{import_id}/vex",
        params={"assessment_id": assessment_id},
        headers=H,
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    ("metadata_component", "serial_number", "expected_code"),
    [
        (False, True, "product_identity_missing"),
        (True, False, "source_bom_serial_number_missing"),
    ],
)
def test_vex_export_fails_closed_without_source_identity(
    client, metadata_component, serial_number, expected_code
):
    release_id, import_id, assessment_id, _finding_id = _release_with_import(
        metadata_component=metadata_component,
        serial_number=serial_number,
    )
    with SessionLocal() as db:
        with pytest.raises(vex_export.VEXExportConflict) as error:
            vex_export.export_cyclonedx_vex(
                db,
                release_id=release_id,
                import_id=import_id,
                assessment_id=assessment_id,
            )
    assert expected_code in str(error.value)


def test_vex_export_blocks_review_without_evidence_manifest(client, monkeypatch):
    release_id, import_id, assessment_id, finding_id = _release_with_import()
    principal_id, token = _token({"assessment:review", "vex:export"})
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")
    response = client.post(
        f"/sbom/assessment-findings/{finding_id}/decisions",
        headers={"X-API-Key": token, "Idempotency-Key": "vex-review-no-manifest"},
        json={
            "state": "in_triage",
            "detail": "The vulnerability requires a product-specific review.",
        },
    )
    assert response.status_code == 201, response.text
    with SessionLocal() as db:
        with pytest.raises(vex_export.VEXExportConflict) as error:
            vex_export.export_cyclonedx_vex(
                db,
                release_id=release_id,
                import_id=import_id,
                assessment_id=assessment_id,
            )
    assert "evidence_manifest_missing_or_invalid" in str(error.value)
    assert principal_id

def test_vex_export_rejects_service_principals(client, monkeypatch):
    release_id, import_id, assessment_id, _finding_id = _release_with_import()
    _principal_id, token = _token({"vex:export"})
    with SessionLocal() as db:
        credential = db.query(identity.APICredential).filter_by(prefix=token.split("_")[1]).one()
        principal = db.get(identity.Principal, credential.principal_id)
        principal.kind = "service"
        db.commit()
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")

    response = client.post(
        f"/product-releases/{release_id}/sbom/{import_id}/vex",
        params={"assessment_id": assessment_id},
        headers={"X-API-Key": token},
    )
    assert response.status_code == 403
