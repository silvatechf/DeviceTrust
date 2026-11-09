import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from packageurl import PackageURL
from packaging.version import InvalidVersion, Version

MAX_COMPONENTS = 5000
MAX_COMPONENT_NAME = 200
MAX_COMPONENT_VERSION = 100
MAX_PURL_LENGTH = 512
SUPPORTED_CYCLONEDX_SPEC_VERSION = "1.5"
MAX_OSV_QUERIES_PER_IMPORT = 50
OSV_QUERY_CONTRACT_VERSION = "2"
OSV_ENRICHMENT_DEADLINE_SECONDS = 10.0
OSV_CONNECT_TIMEOUT_SECONDS = 2.0
OSV_READ_TIMEOUT_SECONDS = 3.0
OSV_WRITE_TIMEOUT_SECONDS = 2.0
OSV_POOL_TIMEOUT_SECONDS = 1.0
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
            if parsed_purl.version and parsed_purl.version != version.strip():
                raise ValueError(f"Component at index {index} has a purl/version mismatch.")

        parsed.append({
            "name": name.strip().lower(),
            "source_name": name,
            "version": version.strip(),
            "source_version": version,
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


def _osv_query_purl(purl: str) -> str:
    """Return an unversioned PURL for OSV's separate top-level version field."""
    parsed = PackageURL.from_string(purl)
    return PackageURL(
        type=parsed.type,
        namespace=parsed.namespace,
        name=parsed.name,
        version=None,
        qualifiers=parsed.qualifiers,
        subpath=parsed.subpath,
    ).to_string()


def _osv_timeout(remaining: float) -> httpx.Timeout:
    return httpx.Timeout(
        timeout=max(0.001, remaining),
        connect=max(0.001, min(OSV_CONNECT_TIMEOUT_SECONDS, remaining)),
        read=max(0.001, min(OSV_READ_TIMEOUT_SECONDS, remaining)),
        write=max(0.001, min(OSV_WRITE_TIMEOUT_SECONDS, remaining)),
        pool=max(0.001, min(OSV_POOL_TIMEOUT_SECONDS, remaining)),
    )


def scan_osv_with_status(
    components: list[dict],
    *,
    include_component_index: bool = False,
    monotonic=None,
) -> tuple[list[dict], dict]:
    """Perform bounded, deduplicated OSV queries and report coverage explicitly."""
    clock = monotonic or time.monotonic
    started = clock()
    deadline = started + OSV_ENRICHMENT_DEADLINE_SECONDS
    unique_queries: dict[tuple[str, str], list[int]] = {}
    skipped_no_purl = 0
    skipped_invalid_purl = 0
    for index, component in enumerate(components):
        purl = component.get("purl")
        if not purl:
            skipped_no_purl += 1
            continue
        try:
            query_purl = _osv_query_purl(purl)
        except (TypeError, ValueError):
            skipped_invalid_purl += 1
            continue
        key = (query_purl, component["version"])
        unique_queries.setdefault(key, []).append(index)

    hits = []
    queried = 0
    failed = False
    budget_exhausted = False
    deadline_exhausted = False
    try:
        with httpx.Client() as client:
            for (purl, version), indexes in unique_queries.items():
                remaining = deadline - clock()
                if queried >= MAX_OSV_QUERIES_PER_IMPORT:
                    budget_exhausted = True
                    break
                if remaining <= 0:
                    deadline_exhausted = True
                    break
                try:
                    response = client.post(
                        "https://api.osv.dev/v1/query",
                        json={"package": {"purl": purl}, "version": version},
                        timeout=_osv_timeout(remaining),
                    )
                    response.raise_for_status()
                    payload = response.json()
                except (httpx.HTTPError, ValueError, TypeError):
                    failed = True
                    queried += 1
                    continue

                queried += 1
                if not isinstance(payload, dict) or not isinstance(payload.get("vulns", []), list):
                    failed = True
                    continue

                for vulnerability in payload.get("vulns", []):
                    if not isinstance(vulnerability, dict):
                        failed = True
                        continue
                    vuln_id = vulnerability.get("id")
                    if not isinstance(vuln_id, str) or not vuln_id.strip():
                        failed = True
                        continue
                    database_specific = vulnerability.get("database_specific")
                    severity = (
                        database_specific.get("severity", "unknown")
                        if isinstance(database_specific, dict)
                        else "unknown"
                    )
                    if not isinstance(severity, str):
                        severity = "unknown"
                    for component_index in indexes:
                        finding = {
                            "component": components[component_index]["name"],
                            "version": components[component_index]["version"],
                            "vuln_id": vuln_id,
                            "severity": severity.lower(),
                            "fixed_in": None,
                            "source": "osv",
                        }
                        if include_component_index:
                            finding["component_index"] = component_index
                        hits.append(finding)
    except httpx.HTTPError:
        failed = True

    deduplicated = sum(len(indexes) - 1 for indexes in unique_queries.values())
    incomplete = failed or budget_exhausted or deadline_exhausted or skipped_no_purl > 0 or skipped_invalid_purl > 0
    status = {
        "status": "incomplete" if incomplete else "complete",
        "source": "osv",
        "queried": queried,
        "query_candidates": len(unique_queries),
        "deduplicated_occurrences": deduplicated,
        "skipped_without_purl": skipped_no_purl,
        "skipped_invalid_purl": skipped_invalid_purl,
        "query_limit": MAX_OSV_QUERIES_PER_IMPORT,
        "deadline_seconds": OSV_ENRICHMENT_DEADLINE_SECONDS,
        "budget_exhausted": budget_exhausted,
        "deadline_exhausted": deadline_exhausted,
        "request_failures": failed,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    return hits, status



async def scan_osv_with_status_async(
    components: list[dict],
    *,
    include_component_index: bool = False,
) -> tuple[list[dict], dict]:
    """Run product-import OSV enrichment against one absolute deadline."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + OSV_ENRICHMENT_DEADLINE_SECONDS
    unique_queries: dict[tuple[str, str], list[int]] = {}
    skipped_no_purl = 0
    skipped_invalid_purl = 0
    hits = []
    queried = 0
    failed = False
    budget_exhausted = False
    deadline_exhausted = False

    try:
        async with asyncio.timeout_at(deadline):
            for index, component in enumerate(components):
                purl = component.get("purl")
                if not purl:
                    skipped_no_purl += 1
                    continue
                try:
                    query_purl = _osv_query_purl(purl)
                except (TypeError, ValueError):
                    skipped_invalid_purl += 1
                    continue
                unique_queries.setdefault((query_purl, component["version"]), []).append(index)

            async with httpx.AsyncClient() as client:
                for (purl, version), indexes in unique_queries.items():
                    remaining = deadline - loop.time()
                    if queried >= MAX_OSV_QUERIES_PER_IMPORT:
                        budget_exhausted = True
                        break
                    if remaining <= 0:
                        deadline_exhausted = True
                        break
                    queried += 1
                    try:
                        response = await client.post(
                            "https://api.osv.dev/v1/query",
                            json={"package": {"purl": purl}, "version": version},
                            timeout=_osv_timeout(remaining),
                        )
                        response.raise_for_status()
                        payload = response.json()
                    except (httpx.HTTPError, ValueError, TypeError):
                        failed = True
                        continue

                    if not isinstance(payload, dict) or not isinstance(payload.get("vulns", []), list):
                        failed = True
                        continue
                    for vulnerability in payload.get("vulns", []):
                        if not isinstance(vulnerability, dict):
                            failed = True
                            continue
                        vuln_id = vulnerability.get("id")
                        if not isinstance(vuln_id, str) or not vuln_id.strip():
                            failed = True
                            continue
                        database_specific = vulnerability.get("database_specific")
                        severity = (
                            database_specific.get("severity", "unknown")
                            if isinstance(database_specific, dict)
                            else "unknown"
                        )
                        if not isinstance(severity, str):
                            severity = "unknown"
                        for component_index in indexes:
                            finding = {
                                "component": components[component_index]["name"],
                                "version": components[component_index]["version"],
                                "vuln_id": vuln_id,
                                "severity": severity.lower(),
                                "fixed_in": None,
                                "source": "osv",
                            }
                            if include_component_index:
                                finding["component_index"] = component_index
                            hits.append(finding)
    except TimeoutError:
        deadline_exhausted = True
    except httpx.HTTPError:
        failed = True

    deduplicated = sum(len(indexes) - 1 for indexes in unique_queries.values())
    incomplete = (
        failed or budget_exhausted or deadline_exhausted
        or skipped_no_purl > 0 or skipped_invalid_purl > 0
    )
    return hits, {
        "status": "incomplete" if incomplete else "complete",
        "source": "osv",
        "queried": queried,
        "query_candidates": len(unique_queries),
        "deduplicated_occurrences": deduplicated,
        "skipped_without_purl": skipped_no_purl,
        "skipped_invalid_purl": skipped_invalid_purl,
        "query_limit": MAX_OSV_QUERIES_PER_IMPORT,
        "deadline_seconds": OSV_ENRICHMENT_DEADLINE_SECONDS,
        "budget_exhausted": budget_exhausted,
        "deadline_exhausted": deadline_exhausted,
        "request_failures": failed,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


async def scan_with_metadata_async(
    components: list[dict], *, include_component_index: bool = False
) -> tuple[list[dict], dict]:
    """Product-import scanner; OSV requests are cancellable at the total deadline."""
    hits = scan_local(components, include_component_index=include_component_index)
    if os.getenv("DEVICETRUST_OSV") != "1":
        return hits, {"status": "disabled", "source": "osv"}
    osv_hits, status = await scan_osv_with_status_async(
        components, include_component_index=include_component_index
    )
    return hits + osv_hits, status

def scan_osv(
    components: list[dict], *, include_component_index: bool = False
) -> list[dict]:
    """Compatibility wrapper for callers that only consume findings."""
    findings, _ = scan_osv_with_status(
        components, include_component_index=include_component_index
    )
    return findings


def scan_with_metadata(
    components: list[dict], *, include_component_index: bool = False
) -> tuple[list[dict], dict]:
    hits = scan_local(components, include_component_index=include_component_index)
    if os.getenv("DEVICETRUST_OSV") != "1":
        return hits, {"status": "disabled", "source": "osv"}
    osv_hits, osv_status = scan_osv_with_status(
        components, include_component_index=include_component_index
    )
    return hits + osv_hits, osv_status


def scan(
    components: list[dict], *, include_component_index: bool = False
) -> list[dict]:
    findings, _ = scan_with_metadata(
        components, include_component_index=include_component_index
    )
    return findings
