"""Explainable, source-aware applicability signals for assessment findings.

These states are evidence descriptions, not VEX statements or legal conclusions.
"""

from typing import Any

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def assess_finding(finding: dict[str, Any], component: dict[str, Any]) -> dict[str, Any]:
    source = finding.get("source")

    if source == "osv":
        query = finding.get("osv_query")
        if not isinstance(query, dict):
            return {
                "status": "unknown",
                "basis": "missing_osv_query_evidence",
            }
        package_url = query.get("package_url")
        version = query.get("version")
        checked_at = query.get("checked_at")
        if (
            query.get("endpoint") != OSV_QUERY_URL
            or not isinstance(package_url, str)
            or not package_url
            or not isinstance(version, str)
            or version != component.get("version")
            or not isinstance(checked_at, str)
            or not checked_at
        ):
            return {
                "status": "unknown",
                "basis": "invalid_osv_query_evidence",
            }
        return {
            "status": "osv_reported_affected",
            "basis": "osv_package_version_query",
            "provider": "OSV",
            "endpoint": OSV_QUERY_URL,
            "package_url": package_url,
            "queried_version": version,
            "vulnerability_id": finding.get("vuln_id"),
            "checked_at": checked_at,
            "interpretation": (
                "OSV returned this vulnerability for the queried package and version. "
                "This provider match is not independent vendor confirmation or a VEX decision."
            ),
        }

    if source == "local-demo":
        return {
            "status": "synthetic_candidate",
            "basis": "local_demo_pep440_fixed_version_comparison",
            "component_version": component.get("version"),
            "fixed_in": finding.get("fixed_in"),
            "interpretation": (
                "Synthetic demonstration advisory only; the generic version comparison "
                "is not an ecosystem-specific or vendor-confirmed affected-range decision."
            ),
        }

    return {
        "status": "unknown",
        "basis": "unsupported_finding_source",
    }
