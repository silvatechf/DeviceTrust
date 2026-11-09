from app import applicability


def test_osv_match_is_recorded_as_provider_reported_affected_not_vendor_decision():
    component = {
        "purl": "pkg:pypi/example@1.2.3",
        "version": "1.2.3",
    }
    finding = {
        "source": "osv",
        "vuln_id": "GHSA-example",
        "osv_query": {
            "endpoint": applicability.OSV_QUERY_URL,
            "package_url": "pkg:pypi/example",
            "component_purl": "pkg:pypi/example@1.2.3",
            "version": "1.2.3",
            "checked_at": "2026-11-09T10:00:00+00:00",
        },
    }

    result = applicability.assess_finding(finding, component)

    assert result["status"] == "osv_reported_affected"
    assert result["basis"] == "osv_package_version_query"
    assert result["queried_version"] == "1.2.3"
    assert result["component_purl"] == "pkg:pypi/example@1.2.3"
    assert "not independent vendor confirmation" in result["interpretation"]


def test_local_demo_finding_remains_a_synthetic_candidate():
    result = applicability.assess_finding(
        {
            "source": "local-demo",
            "fixed_in": "2.0.0",
        },
        {"version": "1.9.0"},
    )

    assert result["status"] == "synthetic_candidate"
    assert result["basis"] == "local_demo_pep440_fixed_version_comparison"
    assert result["fixed_in"] == "2.0.0"
    assert "not an ecosystem-specific" in result["interpretation"]


def test_osv_finding_without_valid_query_evidence_fails_to_unknown():
    result = applicability.assess_finding(
        {"source": "osv", "vuln_id": "CVE-2026-1234"},
        {"version": "1.0.0", "purl": "pkg:generic/example@1.0.0"},
    )

    assert result == {
        "status": "unknown",
        "basis": "missing_osv_query_evidence",
    }


def test_osv_query_version_mismatch_fails_to_unknown():
    result = applicability.assess_finding(
        {
            "source": "osv",
            "vuln_id": "CVE-2026-1234",
            "osv_query": {
                "endpoint": applicability.OSV_QUERY_URL,
                "package_url": "pkg:generic/example",
                "component_purl": "pkg:generic/example@1.0.0",
                "version": "9.9.9",
                "checked_at": "2026-11-09T10:00:00+00:00",
            },
        },
        {"version": "1.0.0"},
    )

    assert result["status"] == "unknown"
    assert result["basis"] == "invalid_osv_query_evidence"


def test_unsupported_finding_source_is_not_promoted_to_affected():
    result = applicability.assess_finding(
        {"source": "third-party-unknown"},
        {"version": "1.0.0"},
    )

    assert result["status"] == "unknown"


def test_osv_query_purl_must_match_component_identity():
    result = applicability.assess_finding(
        {
            "source": "osv",
            "vuln_id": "CVE-2026-1234",
            "osv_query": {
                "endpoint": applicability.OSV_QUERY_URL,
                "package_url": "pkg:generic/other-package",
                "component_purl": "pkg:generic/example@1.0.0",
                "version": "1.0.0",
                "checked_at": "2026-11-09T10:00:00+00:00",
            },
        },
        {"version": "1.0.0", "purl": "pkg:generic/example@1.0.0"},
    )

    assert result["status"] == "unknown"
    assert result["basis"] == "invalid_osv_query_evidence"
