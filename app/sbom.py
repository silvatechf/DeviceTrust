import json
import os
import re
from pathlib import Path

import httpx
from packaging.version import InvalidVersion, Version

MAX_COMPONENTS = 5000
ADVISORIES = Path(__file__).parent / "data" / "advisories.json"


def parse_cyclonedx(doc: dict) -> list[dict]:
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX" or not isinstance(doc.get("components"), list):
        raise ValueError("Not a CycloneDX JSON document with a 'components' list.")
    if len(doc["components"]) > MAX_COMPONENTS:
        raise ValueError(f"Too many components (max {MAX_COMPONENTS}).")
    out = []
    for component in doc["components"]:
        if isinstance(component, dict) and component.get("name") and component.get("version"):
            out.append({
                "name": str(component["name"]).lower(),
                "version": str(component["version"]),
                "purl": component.get("purl"),
            })
    return out


_LOOSE = re.compile(r"^v?(\d+(?:\.\d+)*)([a-z]?)$")


def _lt(a: str, b: str) -> bool:
    try:
        return Version(a) < Version(b)
    except InvalidVersion:
        pass
    match_a, match_b = _LOOSE.match(a.lower()), _LOOSE.match(b.lower())
    if not (match_a and match_b):
        return False

    def key(match):
        return tuple(int(part) for part in match.group(1).split(".")), match.group(2)

    return key(match_a) < key(match_b)


def scan_local(components: list[dict]) -> list[dict]:
    advisories = json.loads(ADVISORIES.read_text())
    hits = []
    for component in components:
        for advisory in advisories:
            if advisory["package"] == component["name"] and _lt(component["version"], advisory["fixed"]):
                hits.append({
                    "component": component["name"],
                    "version": component["version"],
                    "vuln_id": advisory["id"],
                    "severity": advisory["severity"],
                    "fixed_in": advisory["fixed"],
                    "source": "local",
                })
    return hits


def scan_osv(components: list[dict]) -> list[dict]:
    """Optional online lookup (DEVICETRUST_OSV=1). Only components with a purl are queried."""
    hits = []
    with httpx.Client(timeout=8) as client:
        for component in (item for item in components if item.get("purl")):
            try:
                response = client.post(
                    "https://api.osv.dev/v1/query",
                    json={"package": {"purl": component["purl"]}},
                )
                response.raise_for_status()
            except httpx.HTTPError:
                continue
            for vulnerability in response.json().get("vulns", []):
                severity = str(vulnerability.get("database_specific", {}).get("severity", "unknown")).lower()
                hits.append({
                    "component": component["name"],
                    "version": component["version"],
                    "vuln_id": vulnerability["id"],
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
