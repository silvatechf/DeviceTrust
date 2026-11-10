import pytest
from sqlalchemy import select

from app import audit, identity, vex_export
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
    _principal_id, token = _token({"assessment:review", "vex:export"})
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



def test_vex_export_end_to_end_with_evidence_signature_and_independent_approval(
    client, monkeypatch
):
    import base64

    from app import decision_signatures
    from .test_decision_signatures import _keypair, _register

    release_id, import_id, assessment_id, finding_id = _release_with_import()
    artifact_response = client.post(
        "/evidence",
        headers=H,
        json={
            "source_type": "manual",
            "attribute": "firmware_note",
            "value": "Synthetic evidence supporting the reviewed vulnerability decision.",
        },
    )
    assert artifact_response.status_code == 201, artifact_response.text
    observation_id = artifact_response.json()["id"]
    artifact_response = client.post(
        f"/evidence/{observation_id}/artifacts",
        headers={**H, "Content-Type": "application/octet-stream"},
        content=b"synthetic evidence artifact for VEX export integration test",
    )
    assert artifact_response.status_code == 201, artifact_response.text
    artifact_id = artifact_response.json()["id"]

    author_id, author_token = _token(
        {
            "assessment:review",
            "assessment:sign",
            "assessment:read",
            "evidence:read",
            "vex:export",
        }
    )
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")
    author_headers = {"X-API-Key": author_token}
    decision_response = client.post(
        f"/sbom/assessment-findings/{finding_id}/decisions",
        headers={
            **author_headers,
            "Idempotency-Key": f"vex-e2e-{finding_id}",
        },
        json={
            "state": "in_triage",
            "detail": "Synthetic review completed for the end-to-end VEX export test.",
            "evidence_references": [artifact_id],
        },
    )
    assert decision_response.status_code == 201, decision_response.text
    decision_id = decision_response.json()["id"]

    manifest_response = client.post(
        f"/sbom/decisions/{decision_id}/evidence-manifest",
        headers=author_headers,
        json={"artifact_ids": [artifact_id]},
    )
    assert manifest_response.status_code == 201, manifest_response.text
    assert manifest_response.json()["integrity_valid"] is True

    author_private, author_public = _keypair()
    author_key_id, _ = _register(author_id, author_public)
    signing_payload = client.get(
        f"/sbom/decisions/{decision_id}/signing-payload",
        params={"key_id": author_key_id},
        headers=author_headers,
    )
    assert signing_payload.status_code == 200, signing_payload.text
    signing_bytes = base64.b64decode(
        signing_payload.json()["signing_payload_base64"], validate=True
    )
    signature_response = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers=author_headers,
        json={
            "key_id": author_key_id,
            "signature": base64.b64encode(author_private.sign(signing_bytes)).decode(
                "ascii"
            ),
        },
    )
    assert signature_response.status_code == 201, signature_response.text
    signature_status = client.get(
        f"/sbom/decisions/{decision_id}/signature",
        headers=author_headers,
    )
    assert signature_status.status_code == 200
    assert signature_status.json()["trust_valid"] is True

    approver_private, approver_public = _keypair()
    with SessionLocal() as db:
        approver, _credential, approver_token = identity.create_principal(
            db,
            name="Independent VEX integration approver",
            kind="operator",
            scopes={"assessment:approve", "assessment:read"},
        )
        approval_key = decision_signatures.register_public_key(
            db,
            principal_id=approver.id,
            public_key_pem=approver_public,
            purpose="decision-approval",
        )
        approval_key_id = approval_key.id
        db.commit()
    approver_headers = {"X-API-Key": approver_token}
    approval_payload = client.get(
        f"/sbom/decisions/{decision_id}/approval-payload",
        params={"key_id": approval_key_id},
        headers=approver_headers,
    )
    assert approval_payload.status_code == 200, approval_payload.text
    approval_bytes = base64.b64decode(
        approval_payload.json()["signing_payload_base64"], validate=True
    )
    approval_response = client.post(
        f"/sbom/decisions/{decision_id}/approval",
        headers=approver_headers,
        json={
            "key_id": approval_key_id,
            "approved_at": approval_payload.json()["approved_at"],
            "signature": base64.b64encode(
                approver_private.sign(approval_bytes)
            ).decode("ascii"),
        },
    )
    assert approval_response.status_code == 201, approval_response.text
    approval_status = client.get(
        f"/sbom/decisions/{decision_id}/approval",
        headers=author_headers,
    )
    assert approval_status.status_code == 200
    assert approval_status.json()["approval_policy_satisfied"] is True

    export_url = f"/product-releases/{release_id}/sbom/{import_id}/vex"
    export_params = {"assessment_id": assessment_id}
    first_export = client.post(
        export_url, params=export_params, headers=author_headers
    )
    assert first_export.status_code == 200, first_export.text
    exported = first_export.json()
    assert exported["decision_count"] == 1
    assert exported["vulnerability_count"] == 1
    vulnerability = exported["bom"]["vulnerabilities"][0]
    assert vulnerability["id"] == "CVE-2026-12345"
    assert vulnerability["analysis"]["state"] == "in_triage"
    assert vulnerability["affects"] == [{"ref": "openssl-3"}]

    retry_export = client.post(
        export_url, params=export_params, headers=author_headers
    )
    assert retry_export.status_code == 200, retry_export.text
    assert retry_export.json()["bom"] == exported["bom"]
    assert retry_export.json()["bom_sha256"] == exported["bom_sha256"]
