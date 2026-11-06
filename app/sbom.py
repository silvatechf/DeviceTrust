import json
import os
from pathlib import Path

import httpx
from packageurl import PackageURL
from packaging.version import InvalidVersion, Version

MAX_COMPONENTS = 5000
MAX_COMPONENT_NAME = 200
MAX_COMPONENT_VERSION = 100
MAX_PURL_LENGTH = 512
SUPPORTED_CYCLONEDX_SPEC_VERSION = "1.5"
ADVISORIES = Path(__file__).parent / "data" / "advisories.json"


def parse_cyclonedx(doc: dict) -> list[dict]:
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ValueError("Document must declare bomFormat='CycloneDX'.")
    spec_version = doc.get("specVersion")
    if spec_version != SUPPORTED_CYCLONEDX_SPEC_VERSION:
        raise ValueError(
            f"Unsupported or missing CycloneDX specVersion; expected {SUPPORTED_CYCLONEDX_SPEC_VERSION}."
        )
    components = doc.get("components")
    if not isinstance(components, list):
        raise ValueError("CycloneDX document must contain a components array.")
    if len(components) > MAX_COMPONENTS:
        raise ValueError(f"Too many components (max {MAX_COMPONENTS}).")

    parsed = []
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise ValueError(f"Component at index {index} must be an object.")
        name = component.get("name")
        version = component.get("version")
        if not isinstance(name, str) or not name.strip() or len(name) > MAX_COMPONENT_NAME:
            raise ValueError(f"Component at index {index} has an invalid name.")
        if not isinstance(version, str) or not version.strip() or len(version) > MAX_COMPONENT_VERSION:
            raise ValueError(f"Component at index {index} has an invalid version.")

        purl = component.get("purl")
        if purl is not None:
            if not isinstance(purl, str) or len(purl) > MAX_PURL_LENGTH:
                raise ValueError(f"Component at index {index} has an invalid purl.")
            try:
                parsed_purl = PackageURL.from_string(purl)
            except (TypeError, ValueError):
                raise ValueError(f"Component at index {index} has an invalid purl.") from None
            if parsed_purl.version and parsed_purl.version != version:
                raise ValueError(f"Component at index {index} has a purl/version mismatch.")

        parsed.append({
            "name": name.strip().lower(),
            "source_name": name.strip(),
            "version": version.strip(),
            "purl": purl,
        })
    return parsed


def _lt(a: str, b: str) -> bool:
    try:
        return Version(a) < Version(b)
    except InvalidVersion:
        return False


def scan_local(
    components: list[dict], *, include_component_index: bool = False
) -> list[dict]:
    advisories = json.loads(ADVISORIES.read_text(encoding="utf-8"))
    hits = []
    for component_index, component in enumerate(components):
        purl = component.get("purl")
        if not purl:
            continue
        try:
            parsed_purl = PackageURL.from_string(purl)
        except (TypeError, ValueError):
            continue
        for advisory in advisories:
            same_package = (
                advisory["purl_type"] == parsed_purl.type
                and advisory["package"].lower() == parsed_purl.name.lower()
            )
            if same_package and _lt(component["version"], advisory["fixed"]):
                finding = {
                    "component": component["name"],
                    "version": component["version"],
                    "vuln_id": advisory["id"],
                    "severity": advisory["severity"],
                    "fixed_in": advisory["fixed"],
                    "source": "local-demo",
                }
                if include_component_index:
                    finding["component_index"] = component_index
                hits.append(finding)
    return hits


def scan_osv(
    components: list[dict], *, include_component_index: bool = False
) -> list[dict]:
    """Optional OSV lookup scoped to each exact package URL and component version."""
    hits = []
    with httpx.Client(timeout=8) as client:
        for component_index, component in enumerate(components):
            if not component.get("purl"):
                continue
            try:
                response = client.post(
                    "https://api.osv.dev/v1/query",
                    json={
                        "package": {"purl": component["purl"]},
                        "version": component["version"],
                    },
                )
                response.raise_for_status()
                payload = response.json()
            except (httpx.HTTPError, ValueError, TypeError):
                continue

            if not isinstance(payload, dict):
                continue
            vulnerabilities = payload.get("vulns", [])
            if not isinstance(vulnerabilities, list):
                continue

            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                vuln_id = vulnerability.get("id")
                if not isinstance(vuln_id, str) or not vuln_id.strip():
                    continue

                database_specific = vulnerability.get("database_specific")
                severity = (
                    database_specific.get("severity", "unknown")
                    if isinstance(database_specific, dict)
                    else "unknown"
                )
                if not isinstance(severity, str):
                    severity = "unknown"

                finding = {
                    "component": component["name"],
                    "version": component["version"],
                    "vuln_id": vuln_id,
                    "severity": severity.lower(),
                    "fixed_in": None,
                    "source": "osv",
                }
                if include_component_index:
                    finding["component_index"] = component_index
                hits.append(finding)
    return hits


def scan(
    components: list[dict], *, include_component_index: bool = False
) -> list[dict]:
    hits = scan_local(components, include_component_index=include_component_index)
    if os.getenv("DEVICETRUST_OSV") == "1":
        hits += scan_osv(components, include_component_index=include_component_index)
    return hits
