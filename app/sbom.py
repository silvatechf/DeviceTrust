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
ADVISORIES = Path(__file__).parent / "data" / "advisories.json"


def parse_cyclonedx(doc: dict) -> list[dict]:
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ValueError("Document must declare bomFormat='CycloneDX'.")
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

        parsed.append({"name": name.strip().lower(), "version": version.strip(), "purl": purl})
    return parsed


def _lt(a: str, b: str) -> bool:
    try:
        return Version(a) < Version(b)
    except InvalidVersion:
        return False


def scan_local(components: list[dict]) -> list[dict]:
    advisories = json.loads(ADVISORIES.read_text(encoding="utf-8"))
    hits = []
    for component in components:
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
                hits.append({
                    "component": component["name"],
                    "version": component["version"],
                    "vuln_id": advisory["id"],
                    "severity": advisory["severity"],
                    "fixed_in": advisory["fixed"],
                    "source": "local-demo",
                })
    return hits


def scan_osv(components: list[dict]) -> list[dict]:
    """Optional OSV lookup scoped to each exact package URL and component version."""
    hits = []
    with httpx.Client(timeout=8) as client:
        for component in (item for item in components if item.get("purl")):
            try:
                response = client.post(
                    "https://api.osv.dev/v1/query",
                    json={
                        "package": {"purl": component["purl"]},
                        "version": component["version"],
                    },
                )
                response.raise_for_status()
                vulnerabilities = response.json().get("vulns", [])
            except (httpx.HTTPError, ValueError, TypeError):
                continue
            for vulnerability in vulnerabilities:
                vuln_id = vulnerability.get("id")
                if not isinstance(vuln_id, str):
                    continue
                severity = str(vulnerability.get("database_specific", {}).get("severity", "unknown")).lower()
                hits.append({
                    "component": component["name"],
                    "version": component["version"],
                    "vuln_id": vuln_id,
                    "severity": severity,
                    "fixed_in": None,
                    "source": "osv",
                })
    return hits


def scan(components: list[dict]) -> list[dict]:
    hits = scan_local(components)
    if os.getenv("DEVICETRUST_OSV") == "1":
        hits += scan_osv(components)
    return hits
