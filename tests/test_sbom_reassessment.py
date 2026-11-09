import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from app import product_sbom
from app.db import ProductFinding, SBOMAssessment, SBOMComponent, SessionLocal

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
    with SessionLocal() as db:
        component = db.query(SBOMComponent).filter_by(
            sbom_import_id=import_id
        ).one()
        legacy_finding = ProductFinding(
            sbom_component_id=component.id,
            vuln_id="CVE-2099-TRIAGE",
            severity="medium",
            source="legacy-test",
            status="accepted",
            justification="Previously reviewed evidence remains separate.",
        )
        db.add(legacy_finding)
        db.commit()
        legacy_finding_id = legacy_finding.id
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

    async def fake_intelligence(findings):
        enriched = [
            {
                **finding,
                "intelligence": {
                    "kev": {"status": "listed", "catalog_version": "2026.11.04"},
                    "epss": {
                        "status": "scored",
                        "score": 0.9,
                        "percentile": 0.99,
                        "score_date": "2026-11-08",
                    },
                },
            }
            for finding in findings
        ]
        return enriched, {
            "kev": {"status": "complete", "catalog_version": "2026.11.04"},
            "epss": {"status": "complete", "scored_cve_count": 1},
        }

    monkeypatch.setattr(product_sbom.intelligence, "enrich_findings", fake_intelligence)
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
    assert first.json()["status"] == "complete"
    assert first.json()["finding_count"] == 1
    assert len(calls) == 1
    with SessionLocal() as db:
        assert db.query(ProductFinding).count() == legacy_findings_before
        preserved = db.get(ProductFinding, legacy_finding_id)
        assert preserved is not None
        assert preserved.status == "accepted"
        assert preserved.justification == "Previously reviewed evidence remains separate."

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
    assert findings.json()[0]["intelligence"]["kev"]["status"] == "listed"
    assert findings.json()[0]["intelligence"]["epss"]["score"] == 0.9
    assert findings.json()[0]["applicability"]["status"] == "synthetic_candidate"
    assert findings.json()[0]["applicability"]["fixed_in"] == "3.0.1"

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
    with pytest.raises(RuntimeError, match="malformed or unscoped finding"):
        client.post(
            f"/sbom/imports/{import_id}/assessments",
            headers={**H, "Idempotency-Key": "malformed-finding"},
        )

    with SessionLocal() as db:
        assert db.query(SBOMAssessment).filter_by(
            sbom_import_id=import_id
        ).count() == 0



def test_concurrent_reassessment_requests_with_same_key_create_one_run(
    client, monkeypatch
):
    import_id = _import(client)
    request_count = 4
    barrier = Barrier(request_count)
    scan_count = []

    async def fake_scan(components, *, include_component_index=False):
        scan_count.append(1)
        await asyncio.sleep(0.05)
        return [], {"status": "disabled", "source": "osv"}

    monkeypatch.setattr(product_sbom.sbom, "scan_with_metadata_async", fake_scan)

    def submit(_):
        from fastapi.testclient import TestClient

        from app.main import app

        with TestClient(app) as concurrent_client:
            barrier.wait(timeout=10)
            return concurrent_client.post(
                f"/sbom/imports/{import_id}/assessments",
                headers={**H, "Idempotency-Key": "concurrent-same-key"},
            )

    with ThreadPoolExecutor(max_workers=request_count) as executor:
        responses = list(executor.map(submit, range(request_count)))

    assert all(response.status_code in {200, 201} for response in responses)
    assert sum(response.status_code == 201 for response in responses) == 1
    assert len({
        response.json()["id"] for response in responses
    }) == 1
    history = client.get(
        f"/sbom/imports/{import_id}/assessments", headers=H
    )
    assert history.status_code == 200
    assert len(history.json()) == 1


def test_reassessment_persists_osv_provider_reported_applicability(client, monkeypatch):
    import_id = _import(client)

    async def fake_scan(components, *, include_component_index=False):
        assert include_component_index is True
        return [{
            "component_index": 0,
            "vuln_id": "CVE-2026-1234",
            "severity": "high",
            "fixed_in": None,
            "source": "osv",
            "osv_query": {
                "endpoint": "https://api.osv.dev/v1/query",
                "package_url": "pkg:generic/openssl",
                "component_purl": "pkg:generic/openssl@3.0.0",
                "version": "3.0.0",
                "checked_at": "2026-11-09T10:00:00+00:00",
            },
        }], {"status": "complete", "source": "osv"}

    async def fake_intelligence(findings):
        return findings, {
            "kev": {"status": "disabled", "source": "cisa-kev"},
            "epss": {"status": "disabled", "source": "first-epss"},
        }

    monkeypatch.setattr(product_sbom.sbom, "scan_with_metadata_async", fake_scan)
    monkeypatch.setattr(product_sbom.intelligence, "enrich_findings", fake_intelligence)
    monkeypatch.setenv("DEVICETRUST_OSV", "1")
    monkeypatch.delenv("DEVICETRUST_KEV", raising=False)
    monkeypatch.delenv("DEVICETRUST_EPSS", raising=False)

    created = client.post(
        f"/sbom/imports/{import_id}/assessments",
        headers={**H, "Idempotency-Key": "osv-applicability-001"},
    )
    assert created.status_code == 201, created.text

    findings = client.get(
        f"/sbom/imports/{import_id}/assessments/{created.json()['id']}/findings",
        headers=H,
    )
    assert findings.status_code == 200
    applicability = findings.json()[0]["applicability"]
    assert applicability["status"] == "osv_reported_affected"
    assert applicability["package_url"] == "pkg:generic/openssl"
    assert applicability["component_purl"] == "pkg:generic/openssl@3.0.0"
    assert applicability["queried_version"] == "3.0.0"
