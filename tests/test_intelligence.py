import asyncio

import pytest

from app import intelligence


def _kev_entry(cve="CVE-2025-1234"):
    return {
        "cveID": cve,
        "vendorProject": "Example Vendor",
        "product": "Example Product",
        "vulnerabilityName": "Example vulnerability",
        "dateAdded": "2025-01-02",
        "shortDescription": "A synthetic test vulnerability.",
        "requiredAction": "Apply the vendor security update.",
        "dueDate": "2025-02-02",
        "knownRansomwareCampaignUse": "Known",
    }


def test_parse_kev_catalog_preserves_catalog_and_entry_provenance():
    rows, metadata = intelligence.parse_kev_catalog({
        "catalogVersion": "2026.11.04",
        "dateReleased": "2026-11-04T18:52:56.063Z",
        "count": 1,
        "vulnerabilities": [_kev_entry()],
    })

    assert metadata["status"] == "complete"
    assert metadata["catalog_version"] == "2026.11.04"
    assert rows["CVE-2025-1234"]["status"] == "listed"
    assert rows["CVE-2025-1234"]["known_ransomware_campaign_use"] == "Known"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "catalogVersion": "1",
            "dateReleased": "not-a-date",
            "count": 0,
            "vulnerabilities": [],
        },
        {
            "catalogVersion": "1",
            "dateReleased": "2026-11-04T00:00:00Z",
            "count": 2,
            "vulnerabilities": [_kev_entry()],
        },
        {
            "catalogVersion": "1",
            "dateReleased": "2026-11-04T00:00:00Z",
            "count": 1,
            "vulnerabilities": [{"cveID": "not-a-cve"}],
        },
    ],
)
def test_parse_kev_catalog_rejects_invalid_envelopes_and_entries(payload):
    with pytest.raises(ValueError):
        intelligence.parse_kev_catalog(payload)


def test_parse_epss_response_validates_scores_and_date():
    rows = intelligence.parse_epss_response(
        {
            "status": "OK",
            "data": [{
                "cve": "CVE-2025-1234",
                "epss": "0.972240000",
                "percentile": "1.000000000",
                "date": "2026-11-08",
            }],
        },
        {"CVE-2025-1234"},
    )

    assert rows["CVE-2025-1234"] == {
        "status": "scored",
        "score": 0.97224,
        "percentile": 1.0,
        "score_date": "2026-11-08",
        "source": intelligence.EPSS_URL,
    }


@pytest.mark.parametrize("score", ["-0.1", "1.1", "nan", "inf", "invalid"])
def test_parse_epss_response_rejects_out_of_range_or_non_finite_scores(score):
    with pytest.raises(ValueError):
        intelligence.parse_epss_response(
            {
                "status": "OK",
                "data": [{
                    "cve": "CVE-2025-1234",
                    "epss": score,
                    "percentile": "0.5",
                    "date": "2026-11-08",
                }],
            },
            {"CVE-2025-1234"},
        )


def test_parse_epss_response_rejects_unrequested_cves():
    with pytest.raises(ValueError, match="unexpected CVE"):
        intelligence.parse_epss_response(
            {
                "status": "OK",
                "data": [{
                    "cve": "CVE-2025-9999",
                    "epss": "0.5",
                    "percentile": "0.5",
                    "date": "2026-11-08",
                }],
            },
            {"CVE-2025-1234"},
        )


def test_disabled_providers_are_explicit_and_non_cve_findings_are_not_applicable():
    findings, metadata = asyncio.run(
        intelligence.enrich_findings(
            [
                {"vuln_id": "CVE-2025-1234"},
                {"vuln_id": "DT-DEMO-0001"},
            ],
            kev_enabled=False,
            epss_enabled=False,
        )
    )

    assert metadata["kev"]["status"] == "disabled"
    assert metadata["epss"]["status"] == "disabled"
    assert findings[0]["intelligence"]["kev"]["status"] == "not_checked"
    assert findings[0]["intelligence"]["epss"]["status"] == "not_checked"
    assert findings[1]["intelligence"]["kev"]["status"] == "not_applicable"


def test_enrichment_maps_provider_results_to_each_cve(monkeypatch):
    async def fake_kev(_client):
        return {
            "CVE-2025-1234": {
                "status": "listed",
                "catalog_version": "2026.11.04",
                "source": intelligence.KEV_URL,
            }
        }, {"status": "complete", "catalog_version": "2026.11.04"}

    async def fake_epss(_client, cves):
        assert cves == ["CVE-2025-1234", "CVE-2025-5678"]
        return {
            "CVE-2025-1234": {
                "status": "scored",
                "score": 0.9,
                "percentile": 0.99,
                "score_date": "2026-11-08",
                "source": intelligence.EPSS_URL,
            }
        }, {"status": "complete", "scored_cve_count": 1}

    monkeypatch.setattr(intelligence, "_fetch_kev", fake_kev)
    monkeypatch.setattr(intelligence, "_fetch_epss", fake_epss)

    findings, metadata = asyncio.run(
        intelligence.enrich_findings(
            [
                {"vuln_id": "CVE-2025-1234"},
                {"vuln_id": "CVE-2025-5678"},
            ],
            kev_enabled=True,
            epss_enabled=True,
        )
    )

    assert metadata["kev"]["status"] == "complete"
    assert findings[0]["intelligence"]["kev"]["status"] == "listed"
    assert findings[0]["intelligence"]["epss"]["score"] == 0.9
    assert findings[1]["intelligence"]["kev"]["status"] == "not_listed"
    assert findings[1]["intelligence"]["epss"]["status"] == "not_found"


def test_provider_failure_is_incomplete_not_a_clean_result(monkeypatch):
    async def fail(_client):
        raise TimeoutError()

    async def epss_fail(_client, _cves):
        raise TimeoutError()

    monkeypatch.setattr(intelligence, "_fetch_kev", fail)
    monkeypatch.setattr(intelligence, "_fetch_epss", epss_fail)
    findings, metadata = asyncio.run(
        intelligence.enrich_findings(
            [{"vuln_id": "CVE-2025-1234"}],
            kev_enabled=True,
            epss_enabled=True,
        )
    )

    assert metadata["kev"]["status"] == "incomplete"
    assert metadata["epss"]["status"] == "incomplete"
    assert findings[0]["intelligence"]["kev"]["status"] == "unavailable"
    assert findings[0]["intelligence"]["epss"]["status"] == "unavailable"
