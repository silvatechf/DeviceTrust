"""Bounded, provenance-preserving KEV and EPSS enrichment for CVE findings."""

import asyncio
import json
import math
import os
import re
from datetime import datetime, timezone

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
MAX_CVES_PER_ASSESSMENT = 100
EPSS_BATCH_SIZE = 40
MAX_KEV_BYTES = 5 * 1024 * 1024
MAX_EPSS_BYTES = 512 * 1024
REQUEST_TIMEOUT_SECONDS = 8.0


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _date(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _cve(value: object) -> bool:
    return isinstance(value, str) and CVE_PATTERN.fullmatch(value) is not None


def parse_kev_catalog(payload: object) -> tuple[dict[str, dict], dict]:
    """Validate the CISA catalog envelope and return a CVE-indexed snapshot."""
    if not isinstance(payload, dict):
        raise ValueError("KEV catalog must be a JSON object")
    version = payload.get("catalogVersion")
    released = payload.get("dateReleased")
    rows = payload.get("vulnerabilities")
    count = payload.get("count")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("KEV catalogVersion is missing")
    if not isinstance(released, str):
        raise ValueError("KEV dateReleased is missing")
    try:
        datetime.fromisoformat(released.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("KEV dateReleased is invalid") from None
    if not isinstance(rows, list) or not isinstance(count, int) or isinstance(count, bool):
        raise ValueError("KEV count or vulnerabilities is invalid")
    if count != len(rows):
        raise ValueError("KEV declared count does not match catalog rows")

    indexed: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("KEV entry must be an object")
        cve_id = row.get("cveID")
        if not _cve(cve_id):
            raise ValueError("KEV entry has an invalid CVE identifier")
        required = ("vendorProject", "product", "dateAdded", "dueDate", "requiredAction")
        if any(not isinstance(row.get(key), str) or not row[key].strip() for key in required):
            raise ValueError(f"KEV entry {cve_id} is missing required fields")
        if not _date(row["dateAdded"]) or not _date(row["dueDate"]):
            raise ValueError(f"KEV entry {cve_id} has invalid dates")
        if cve_id in indexed:
            raise ValueError(f"KEV catalog contains duplicate CVE {cve_id}")
        ransomware = row.get("knownRansomwareCampaignUse", "Unknown")
        if not isinstance(ransomware, str) or ransomware not in {"Known", "Unknown"}:
            ransomware = "Unknown"
        indexed[cve_id] = {
            "status": "listed",
            "vendor_project": row["vendorProject"],
            "product": row["product"],
            "date_added": row["dateAdded"],
            "due_date": row["dueDate"],
            "known_ransomware_campaign_use": ransomware,
            "required_action": row["requiredAction"],
            "catalog_version": version,
            "catalog_released_at": released,
            "source": KEV_URL,
        }
    return indexed, {
        "status": "complete",
        "source": KEV_URL,
        "catalog_version": version,
        "catalog_released_at": released,
        "catalog_count": count,
        "matched_count": 0,
        "retrieved_at": _utc_now(),
    }


def parse_epss_response(
    payload: object, requested_cves: set[str]
) -> dict[str, dict]:
    """Validate FIRST EPSS values; scores and percentiles are bounded probabilities."""
    if not isinstance(payload, dict) or payload.get("status") != "OK":
        raise ValueError("EPSS response status is not OK")
    rows = payload.get("data")
    if not isinstance(rows, list):
        raise ValueError("EPSS data must be an array")
    indexed: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("EPSS row must be an object")
        cve_id = row.get("cve")
        if not _cve(cve_id) or cve_id not in requested_cves:
            raise ValueError("EPSS returned an unexpected CVE identifier")
        try:
            score = float(row["epss"])
            percentile = float(row["percentile"])
        except (KeyError, TypeError, ValueError):
            raise ValueError(f"EPSS values are invalid for {cve_id}") from None
        if (
            not math.isfinite(score)
            or not math.isfinite(percentile)
            or not 0 <= score <= 1
            or not 0 <= percentile <= 1
            or not _date(row.get("date"))
        ):
            raise ValueError(f"EPSS values are out of range for {cve_id}")
        if cve_id in indexed:
            raise ValueError(f"EPSS returned duplicate CVE {cve_id}")
        indexed[cve_id] = {
            "status": "scored",
            "score": score,
            "percentile": percentile,
            "score_date": row["date"],
            "source": EPSS_URL,
        }
    return indexed


async def _read_bounded(response: httpx.Response, limit: int) -> bytes:
    chunks = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > limit:
            raise ValueError("Intelligence response exceeds the configured size limit")
        chunks.append(chunk)
    return b"".join(chunks)


async def _fetch_kev(client: httpx.AsyncClient) -> tuple[dict, dict]:
    """Fetch CISA's catalog, falling back to CISA's official GitHub mirror."""
    last_error = None
    for source_url in (KEV_URL, KEV_MIRROR_URL):
        try:
            async with client.stream("GET", source_url) as response:
                response.raise_for_status()
                raw = await _read_bounded(response, MAX_KEV_BYTES)
            rows, metadata = parse_kev_catalog(json.loads(raw))
            metadata["source"] = source_url
            metadata["canonical_source"] = KEV_URL
            return rows, metadata
        except (httpx.HTTPError, ValueError, TypeError) as error:
            last_error = error
    raise ValueError(
        f"CISA KEV catalog and official mirror are unavailable: "
        f"{type(last_error).__name__ if last_error else 'unknown error'}"
    )


async def _fetch_epss(
    client: httpx.AsyncClient, cves: list[str]
) -> tuple[dict, dict]:
    indexed: dict[str, dict] = {}
    queried = 0
    for offset in range(0, len(cves), EPSS_BATCH_SIZE):
        batch = cves[offset : offset + EPSS_BATCH_SIZE]
        async with client.stream(
            "GET", EPSS_URL, params={"cve": ",".join(batch)}
        ) as response:
            response.raise_for_status()
            raw = await _read_bounded(response, MAX_EPSS_BYTES)
        parsed = parse_epss_response(json.loads(raw), set(batch))
        indexed.update(parsed)
        queried += len(batch)
    return indexed, {
        "status": "complete",
        "source": EPSS_URL,
        "requested_cve_count": len(cves),
        "scored_cve_count": len(indexed),
        "not_found_count": len(cves) - len(indexed),
        "retrieved_at": _utc_now(),
    }


async def _provider_call(coro, provider: str) -> tuple[dict, dict]:
    try:
        async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
            return await coro
    except (TimeoutError, httpx.HTTPError, ValueError, TypeError) as error:
        return {}, {
            "status": "incomplete",
            "source": KEV_URL if provider == "kev" else EPSS_URL,
            "error_type": type(error).__name__,
            "retrieved_at": _utc_now(),
        }


async def enrich_findings(
    findings: list[dict],
    *,
    kev_enabled: bool | None = None,
    epss_enabled: bool | None = None,
) -> tuple[list[dict], dict]:
    """Enrich CVE findings while preserving provider coverage and per-finding states."""
    kev_enabled = os.getenv("DEVICETRUST_KEV") == "1" if kev_enabled is None else kev_enabled
    epss_enabled = os.getenv("DEVICETRUST_EPSS") == "1" if epss_enabled is None else epss_enabled
    cves = sorted({
        finding["vuln_id"]
        for finding in findings
        if isinstance(finding, dict) and _cve(finding.get("vuln_id"))
    })
    bounded_cves = cves[:MAX_CVES_PER_ASSESSMENT]
    truncated = len(cves) > len(bounded_cves)
    metadata: dict[str, dict] = {}
    kev_rows: dict[str, dict] = {}
    epss_rows: dict[str, dict] = {}

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        calls = []
        if kev_enabled and bounded_cves:
            calls.append(("kev", _provider_call(_fetch_kev(client), "kev")))
        if epss_enabled and bounded_cves:
            calls.append(("epss", _provider_call(_fetch_epss(client, bounded_cves), "epss")))
        results = await asyncio.gather(*(call for _, call in calls))
    for (provider, _), (rows, provider_meta) in zip(calls, results):
        metadata[provider] = provider_meta
        if provider == "kev":
            kev_rows = rows
        else:
            epss_rows = rows

    if not kev_enabled:
        metadata["kev"] = {"status": "disabled", "source": KEV_URL}
    elif not bounded_cves:
        metadata["kev"] = {"status": "not_applicable", "source": KEV_URL}
    if not epss_enabled:
        metadata["epss"] = {"status": "disabled", "source": EPSS_URL}
    elif not bounded_cves:
        metadata["epss"] = {"status": "not_applicable", "source": EPSS_URL}
    if truncated:
        for provider in ("kev", "epss"):
            if metadata[provider]["status"] == "complete":
                metadata[provider]["status"] = "incomplete"
            metadata[provider]["truncated_cve_count"] = len(cves) - len(bounded_cves)

    metadata["kev"]["matched_count"] = sum(cve in kev_rows for cve in bounded_cves)
    enriched = []
    for original in findings:
        finding = dict(original)
        cve_id = finding.get("vuln_id")
        if not _cve(cve_id):
            finding["intelligence"] = {
                "kev": {"status": "not_applicable"},
                "epss": {"status": "not_applicable"},
            }
        else:
            if not kev_enabled:
                kev = {"status": "not_checked"}
            elif cve_id not in bounded_cves:
                kev = {"status": "not_checked", "reason": "assessment_cve_limit"}
            elif metadata["kev"].get("error_type"):
                kev = {"status": "unavailable"}
            else:
                kev = kev_rows.get(cve_id, {"status": "not_listed"})
            if not epss_enabled:
                epss = {"status": "not_checked"}
            elif cve_id not in bounded_cves:
                epss = {"status": "not_checked", "reason": "assessment_cve_limit"}
            elif metadata["epss"].get("error_type"):
                epss = {"status": "unavailable"}
            else:
                epss = epss_rows.get(cve_id, {"status": "not_found"})
            finding["intelligence"] = {"kev": kev, "epss": epss}
        enriched.append(finding)
    return enriched, metadata
