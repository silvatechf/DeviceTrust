from app import product_sbom

from .conftest import H


def _release(client):
    product = client.post(
        "/products",
        json={"manufacturer": "Example Vendor", "product_name": "OSV Fixture"},
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


def test_product_import_persists_and_exposes_osv_coverage(client, monkeypatch):
    release_id = _release(client)
    calls = []
    enrichment = {
        "status": "incomplete",
        "source": "osv",
        "queried": 1,
        "query_candidates": 3,
        "deduplicated_occurrences": 0,
        "skipped_without_purl": 0,
        "query_limit": 50,
        "deadline_seconds": 10.0,
        "deadline_exhausted": True,
        "request_failures": False,
        "checked_at": "2026-11-08T12:00:00+00:00",
    }

    async def fake_scan(components, *, include_component_index=False):
        calls.append(components)
        return [], enrichment

    monkeypatch.setattr(product_sbom.sbom, "scan_with_metadata_async", fake_scan)
    monkeypatch.setenv("DEVICETRUST_OSV", "1")
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{
            "type": "library",
            "name": "openssl",
            "version": "3.0.0",
            "purl": "pkg:generic/openssl@3.0.0",
        }],
    }

    imported = client.post(
        f"/product-releases/{release_id}/sbom",
        json=payload,
        headers=H,
    )
    assert imported.status_code == 201, imported.text
    assert imported.json()["validation_summary"]["enrichment"] == enrichment

    listed = client.get(f"/product-releases/{release_id}/sbom", headers=H)
    assert listed.status_code == 200
    assert listed.json()[0]["validation_summary"]["enrichment"] == enrichment
    assert len(calls) == 1


def test_duplicate_product_import_does_not_repeat_osv_enrichment(client, monkeypatch):
    release_id = _release(client)
    calls = []

    async def fake_scan(components, *, include_component_index=False):
        calls.append(components)
        return [], {"status": "complete", "source": "osv", "queried": 1}

    monkeypatch.setattr(product_sbom.sbom, "scan_with_metadata_async", fake_scan)
    monkeypatch.setenv("DEVICETRUST_OSV", "1")
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{
            "type": "library",
            "name": "openssl",
            "version": "3.0.0",
            "purl": "pkg:generic/openssl@3.0.0",
        }],
    }

    first = client.post(
        f"/product-releases/{release_id}/sbom",
        json=payload,
        headers=H,
    )
    second = client.post(
        f"/product-releases/{release_id}/sbom",
        json=payload,
        headers=H,
    )

    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert first.json()["created"] is True
    assert second.json()["created"] is False
    assert len(calls) == 1
