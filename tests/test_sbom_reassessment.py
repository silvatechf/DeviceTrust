from app import product_sbom
from app.db import ProductFinding, SBOMAssessment, SessionLocal

from .conftest import H


def _import(client):
    product = client.post(
        "/products",
        json={"manufacturer": "Example Vendor", "product_name": "Assessment Fixture"},
        headers=H,
    )
    assert product.status_code == 201
    release = client.post(
        f"/products/{product.json()['id']}/releases",
        json={"version": "1.0.0"},
        headers=H,
    )
    assert release.status_code == 201
    imported = client.post(
        f"/product-releases/{release.json()['id']}/sbom",
        json={
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{
                "type": "library",
                "name": "openssl",
                "version": "3.0.0",
                "purl": "pkg:generic/openssl@3.0.0",
            }],
        },
        headers=H,
    )
    assert imported.status_code == 201
    return imported.json()["id"]


def test_reassessment_persists_versioned_findings_and_is_idempotent(
    client, monkeypatch
):
    import_id = _import(client)
    calls = []

    async def fake_scan(components, *, include_component_index=False):
        calls.append(components)
        assert include_component_index is True
        return [{
            "component_index": 0,
            "vuln_id": "CVE-2099-0001",
            "severity": "high",
            "fixed_in": "3.0.1",
            "source": "local-demo",
        }], {"status": "disabled", "source": "osv"}

    monkeypatch.setattr(product_sbom.sbom, "scan_with_metadata_async", fake_scan)
    monkeypatch.delenv("DEVICETRUST_OSV", raising=False)

    with SessionLocal() as db:
        legacy_findings_before = db.query(ProductFinding).count()

    first = client.post(
        f"/sbom/imports/{import_id}/assessments",
        headers={**H, "Idempotency-Key": "assessment-run-001"},
    )
    repeated = client.post(
        f"/sbom/imports/{import_id}/assessments",
        headers={**H, "Idempotency-Key": "assessment-run-001"},
    )

    assert first.status_code == 201, first.text
    assert repeated.status_code == 200, repeated.text
    assert first.json()["id"] == repeated.json()["id"]
    assert first.json()["created"] is True
    assert repeated.json()["created"] is False
    assert first.json()["status"] == "disabled"
    assert first.json()["finding_count"] == 1
    assert len(calls) == 1
    with SessionLocal() as db:
        assert db.query(ProductFinding).count() == legacy_findings_before

    assessment_id = first.json()["id"]
    history = client.get(
        f"/sbom/imports/{import_id}/assessments", headers=H
    )
    findings = client.get(
        f"/sbom/imports/{import_id}/assessments/{assessment_id}/findings",
        headers=H,
    )
    assert history.status_code == findings.status_code == 200
    assert len(history.json()) == 1
    assert findings.json()[0]["vuln_id"] == "CVE-2099-0001"

    # A deliberate new request identity appends another historical run.
    second = client.post(
        f"/sbom/imports/{import_id}/assessments",
        headers={**H, "Idempotency-Key": "assessment-run-002"},
    )
    assert second.status_code == 201
    assert second.json()["id"] != assessment_id
    assert len(client.get(
        f"/sbom/imports/{import_id}/assessments", headers=H
    ).json()) == 2


def test_reassessment_rejects_idempotency_key_reuse_after_config_change(
    client, monkeypatch
):
    import_id = _import(client)

    async def fake_scan(components, *, include_component_index=False):
        return [], {"status": "disabled", "source": "osv"}

    monkeypatch.setattr(product_sbom.sbom, "scan_with_metadata_async", fake_scan)
    monkeypatch.delenv("DEVICETRUST_OSV", raising=False)
    first = client.post(
        f"/sbom/imports/{import_id}/assessments",
        headers={**H, "Idempotency-Key": "stable-request"},
    )
    assert first.status_code == 201

    monkeypatch.setenv("DEVICETRUST_OSV", "1")
    repeated = client.post(
        f"/sbom/imports/{import_id}/assessments",
        headers={**H, "Idempotency-Key": "stable-request"},
    )
    assert repeated.status_code == 409
    assert "different assessment configuration" in repeated.json()["detail"]

    with SessionLocal() as db:
        assert db.query(SBOMAssessment).filter_by(
            sbom_import_id=import_id
        ).count() == 1



def test_reassessment_rejects_unauthenticated_requests(client):
    import_id = _import(client)
    response = client.post(
        f"/sbom/imports/{import_id}/assessments",
        headers={"Idempotency-Key": "unauthenticated"},
    )
    assert response.status_code == 401


def test_reassessment_rolls_back_malformed_scanner_findings(client, monkeypatch):
    import_id = _import(client)

    async def malformed_scan(components, *, include_component_index=False):
        return [{"component_index": 999}], {"status": "disabled", "source": "osv"}

    monkeypatch.setattr(
        product_sbom.sbom, "scan_with_metadata_async", malformed_scan
    )
    response = client.post(
        f"/sbom/imports/{import_id}/assessments",
        headers={**H, "Idempotency-Key": "malformed-finding"},
    )
    assert response.status_code == 500

    with SessionLocal() as db:
        assert db.query(SBOMAssessment).filter_by(
            sbom_import_id=import_id
        ).count() == 0
