"""Transactional persistence for accepted CycloneDX SBOM imports."""

import hashlib
import json
import os
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import applicability, audit, intelligence, sbom
from .db import (
    Product,
    ProductFinding,
    ProductRelease,
    SBOMAssessment,
    SBOMAssessmentFinding,
    SBOMComponent,
    SBOMImport,
    SessionLocal,
)

PARSER_VERSION = "0.4.0"


def create_product(
    db: Session,
    actor: str,
    manufacturer: str,
    product_name: str,
    external_reference: str | None,
) -> Product:
    audit.acquire_chain_lock(db)
    product = Product(
        manufacturer=manufacturer.strip(),
        product_name=product_name.strip(),
        external_reference=external_reference,
    )
    db.add(product)
    db.flush()
    audit.record(
        db,
        actor,
        "product.create",
        str(product.id),
        {
            "manufacturer": product.manufacturer,
            "product_name": product.product_name,
        },
    )
    db.commit()
    db.refresh(product)
    return product


def create_release(
    db: Session,
    actor: str,
    product_id: int,
    version: str,
    hardware_revision: str | None,
    release_reference: str | None,
) -> ProductRelease:
    audit.acquire_chain_lock(db)
    if db.get(Product, product_id) is None:
        raise LookupError("Product not found")

    release = ProductRelease(
        product_id=product_id,
        version=version.strip(),
        hardware_revision=hardware_revision,
        release_reference=release_reference,
    )
    db.add(release)
    db.flush()
    audit.record(
        db,
        actor,
        "product_release.create",
        str(release.id),
        {"product_id": product_id, "version": release.version},
    )
    db.commit()
    db.refresh(release)
    return release


async def import_cyclonedx(
    db: Session,
    actor: str,
    release_id: int,
    raw_document: bytes,
    document: dict,
    source_type: str,
    source_reference: str | None,
) -> tuple[SBOMImport, bool]:
    parsed_document = sbom.parse_cyclonedx_document(document)
    components = parsed_document["components"]
    bom_metadata = {
        "serial_number": parsed_document["serial_number"],
        "version": parsed_document["version"],
        "version_explicit": parsed_document["version_explicit"],
        "metadata_component": parsed_document["metadata_component"],
    }
    digest = hashlib.sha256(raw_document).hexdigest()

    existing_query = select(SBOMImport).where(
        SBOMImport.product_release_id == release_id,
        SBOMImport.format == "CycloneDX",
        SBOMImport.content_sha256 == digest,
    )
    # Preflight in a separate session: SQLite must acquire BEGIN IMMEDIATE
    # before the write session performs any read.
    with SessionLocal() as lookup_db:
        if lookup_db.get(ProductRelease, release_id) is None:
            raise LookupError("Product release not found")
        existing = lookup_db.scalars(existing_query).first()
        if existing is not None:
            return existing, False

    findings, osv_enrichment = await sbom.scan_with_metadata_async(
        components, include_component_index=True
    )
    findings_by_component: dict[int, list[dict]] = {}
    for finding in findings:
        component_index = finding["component_index"]
        findings_by_component.setdefault(component_index, []).append(finding)

    audit.acquire_chain_lock(db)
    if db.get(ProductRelease, release_id) is None:
        raise LookupError("Product release not found")

    # Recheck after acquiring the serialized writer lock to handle concurrent imports.
    existing = db.scalars(existing_query).first()
    if existing is not None:
        return existing, False

    imported = SBOMImport(
        product_release_id=release_id,
        format="CycloneDX",
        spec_version=document["specVersion"],
        source_type=source_type,
        source_reference=source_reference,
        content_sha256=digest,
        parser_version=PARSER_VERSION,
        status="accepted",
        component_count=len(components),
        bom_metadata=bom_metadata,
        validation_summary={
            "valid": True,
            "component_count": len(components),
            "enrichment": osv_enrichment,
        },
    )

    try:
        db.add(imported)
        db.flush()

        for ordinal, component in enumerate(components):
            occurrence = SBOMComponent(
                sbom_import_id=imported.id,
                ordinal=ordinal,
                name=component["source_name"],
                version=component["source_version"],
                purl=component["purl"],
                bom_ref=component["bom_ref"],
            )
            db.add(occurrence)
            db.flush()

            for finding in findings_by_component.get(ordinal, []):
                db.add(
                    ProductFinding(
                        sbom_component_id=occurrence.id,
                        vuln_id=finding["vuln_id"],
                        severity=finding["severity"],
                        fixed_in=finding["fixed_in"],
                        source=finding["source"],
                    )
                )

        audit.record(
            db,
            actor,
            "sbom.product_import",
            str(imported.id),
            {
                "product_release_id": release_id,
                "content_sha256": digest,
                "component_count": len(components),
            },
        )
        db.commit()
        db.refresh(imported)
        return imported, True
    except IntegrityError:
        db.rollback()
        concurrent = db.scalars(
            select(SBOMImport).where(
                SBOMImport.product_release_id == release_id,
                SBOMImport.format == "CycloneDX",
                SBOMImport.content_sha256 == digest,
            )
        ).first()
        if concurrent is not None:
            return concurrent, False
        raise
    except Exception:
        db.rollback()
        raise


def _component_identity(component: SBOMComponent) -> str | None:
    """Return a version-independent Package URL identity when one is available."""
    if not component.purl:
        return None

    from packageurl import PackageURL

    try:
        parsed = PackageURL.from_string(component.purl)
        return PackageURL(
            type=parsed.type,
            namespace=parsed.namespace,
            name=parsed.name,
            version=None,
            qualifiers=parsed.qualifiers,
            subpath=parsed.subpath,
        ).to_string()
    except (TypeError, ValueError):
        # Persisted PURLs were validated at import time. Treat unexpected legacy
        # values as unidentifiable rather than creating a speculative match.
        return None


def _component_snapshot(component: SBOMComponent) -> dict:
    return {
        "id": component.id,
        "ordinal": component.ordinal,
        "name": component.name,
        "version": component.version,
        "purl": component.purl,
        "bom_ref": component.bom_ref,
    }


def compare_imports(
    db: Session,
    release_id: int,
    from_import_id: int,
    to_import_id: int,
) -> dict:
    """Compare accepted imports without mutating stored SBOM evidence.

    PURL identity excludes only the PURL version. Qualifiers and subpath remain
    part of identity. Duplicate identities and components without a usable PURL
    are never matched speculatively.
    """
    if db.get(ProductRelease, release_id) is None:
        raise LookupError("Product release not found")

    previous = db.get(SBOMImport, from_import_id)
    current = db.get(SBOMImport, to_import_id)
    if (
        previous is None
        or current is None
        or previous.product_release_id != release_id
        or current.product_release_id != release_id
        or previous.status != "accepted"
        or current.status != "accepted"
    ):
        raise LookupError("Accepted SBOM imports not found for product release")

    previous_rows = db.scalars(
        select(SBOMComponent)
        .where(SBOMComponent.sbom_import_id == from_import_id)
        .order_by(SBOMComponent.ordinal)
    ).all()
    current_rows = db.scalars(
        select(SBOMComponent)
        .where(SBOMComponent.sbom_import_id == to_import_id)
        .order_by(SBOMComponent.ordinal)
    ).all()

    previous_groups: dict[str, list[SBOMComponent]] = {}
    current_groups: dict[str, list[SBOMComponent]] = {}
    previous_unidentified = []
    current_unidentified = []

    for component in previous_rows:
        identity = _component_identity(component)
        if identity is None:
            previous_unidentified.append(_component_snapshot(component))
        else:
            previous_groups.setdefault(identity, []).append(component)

    for component in current_rows:
        identity = _component_identity(component)
        if identity is None:
            current_unidentified.append(_component_snapshot(component))
        else:
            current_groups.setdefault(identity, []).append(component)

    added = []
    removed = []
    changed = []
    ambiguous = []
    unchanged = 0
    version_changed = 0
    name_changed = 0

    for identity in sorted(previous_groups.keys() | current_groups.keys()):
        before = previous_groups.get(identity, [])
        after = current_groups.get(identity, [])
        if len(before) > 1 or len(after) > 1:
            ambiguous.append({
                "identity": identity,
                "previous": [_component_snapshot(item) for item in before],
                "current": [_component_snapshot(item) for item in after],
            })
            continue
        if not before:
            added.append(_component_snapshot(after[0]))
            continue
        if not after:
            removed.append(_component_snapshot(before[0]))
            continue

        old_item = before[0]
        new_item = after[0]
        dimensions = []
        if old_item.version != new_item.version:
            dimensions.append("version")
            version_changed += 1
        if old_item.name != new_item.name:
            dimensions.append("name")
            name_changed += 1

        if dimensions:
            changed.append({
                "identity": identity,
                "previous": _component_snapshot(old_item),
                "current": _component_snapshot(new_item),
                "changes": dimensions,
            })
        else:
            unchanged += 1

    added.sort(key=lambda item: (item["purl"] or "", item["ordinal"]))
    removed.sort(key=lambda item: (item["purl"] or "", item["ordinal"]))
    changed.sort(key=lambda item: item["identity"])
    ambiguous.sort(key=lambda item: item["identity"])
    previous_unidentified.sort(key=lambda item: item["ordinal"])
    current_unidentified.sort(key=lambda item: item["ordinal"])

    return {
        "product_release_id": release_id,
        "from_import_id": from_import_id,
        "to_import_id": to_import_id,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "version_changed": version_changed,
            "name_changed": name_changed,
            "unchanged": unchanged,
            "ambiguous": len(ambiguous),
            "unidentified_previous": len(previous_unidentified),
            "unidentified_current": len(current_unidentified),
        },
        "added": added,
        "removed": removed,
        "changed": changed,
        "ambiguous": ambiguous,
        "unidentified": {
            "previous": previous_unidentified,
            "current": current_unidentified,
        },
    }



def _assessment_dict(assessment: SBOMAssessment) -> dict:
    return {
        "id": assessment.id,
        "sbom_import_id": assessment.sbom_import_id,
        "source_fingerprint": assessment.source_fingerprint,
        "status": assessment.status,
        "started_at": assessment.started_at,
        "completed_at": assessment.completed_at,
        "component_count": assessment.component_count,
        "finding_count": assessment.finding_count,
        "enrichment_metadata": assessment.enrichment_metadata,
    }


def list_assessments(db: Session, import_id: int) -> list[dict]:
    imported = db.get(SBOMImport, import_id)
    if imported is None or imported.status != "accepted":
        raise LookupError("Accepted SBOM import not found")
    rows = db.scalars(
        select(SBOMAssessment)
        .where(SBOMAssessment.sbom_import_id == import_id)
        .order_by(SBOMAssessment.started_at, SBOMAssessment.id)
    ).all()
    return [_assessment_dict(row) for row in rows]


def list_assessment_findings(
    db: Session, import_id: int, assessment_id: int
) -> list[dict]:
    assessment = db.get(SBOMAssessment, assessment_id)
    if assessment is None or assessment.sbom_import_id != import_id:
        raise LookupError("SBOM assessment not found")
    rows = db.scalars(
        select(SBOMAssessmentFinding)
        .where(SBOMAssessmentFinding.assessment_id == assessment_id)
        .order_by(
            SBOMAssessmentFinding.sbom_component_id,
            SBOMAssessmentFinding.vuln_id,
            SBOMAssessmentFinding.source,
        )
    ).all()
    return [
        {
            "id": row.id,
            "sbom_component_id": row.sbom_component_id,
            "vuln_id": row.vuln_id,
            "severity": row.severity,
            "fixed_in": row.fixed_in,
            "source": row.source,
            "intelligence": row.intelligence,
            "applicability": row.applicability,
        }
        for row in rows
    ]


async def reassess_import(
    db: Session,
    actor: str,
    import_id: int,
    request_key: str,
) -> tuple[dict, bool]:
    """Reassess immutable imported components and append a historical run."""
    if not request_key or len(request_key) > 128:
        raise ValueError("Idempotency-Key must contain between 1 and 128 characters.")

    request_key_hash = hashlib.sha256(request_key.encode("utf-8")).hexdigest()
    advisory_digest = hashlib.sha256(sbom.ADVISORIES.read_bytes()).hexdigest()
    osv_enabled = os.getenv("DEVICETRUST_OSV") == "1"
    source_configuration = {
        "parser_version": PARSER_VERSION,
        "local_advisories_sha256": advisory_digest,
        "osv": {
            "enabled": osv_enabled,
            "endpoint": "https://api.osv.dev/v1/query",
            "query_contract_version": sbom.OSV_QUERY_CONTRACT_VERSION,
            "query_limit": sbom.MAX_OSV_QUERIES_PER_IMPORT,
            "deadline_seconds": sbom.OSV_ENRICHMENT_DEADLINE_SECONDS,
            "connect_timeout_seconds": sbom.OSV_CONNECT_TIMEOUT_SECONDS,
            "read_timeout_seconds": sbom.OSV_READ_TIMEOUT_SECONDS,
            "write_timeout_seconds": sbom.OSV_WRITE_TIMEOUT_SECONDS,
            "pool_timeout_seconds": sbom.OSV_POOL_TIMEOUT_SECONDS,
        },
        "kev": {
            "enabled": os.getenv("DEVICETRUST_KEV") == "1",
            "endpoint": intelligence.KEV_URL,
            "fallback_endpoint": intelligence.KEV_MIRROR_URL,
        },
        "epss": {
            "enabled": os.getenv("DEVICETRUST_EPSS") == "1",
            "endpoint": intelligence.EPSS_URL,
        },
        "intelligence_cve_limit": intelligence.MAX_CVES_PER_ASSESSMENT,
        "intelligence_timeout_seconds": intelligence.REQUEST_TIMEOUT_SECONDS,
    }
    source_fingerprint = hashlib.sha256(
        json.dumps(
            source_configuration,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    with SessionLocal() as lookup_db:
        imported = lookup_db.get(SBOMImport, import_id)
        if imported is None or imported.status != "accepted":
            raise LookupError("Accepted SBOM import not found")
        existing = lookup_db.scalars(
            select(SBOMAssessment).where(
                SBOMAssessment.sbom_import_id == import_id,
                SBOMAssessment.request_key_hash == request_key_hash,
            )
        ).first()
        if existing is not None:
            if existing.source_fingerprint != source_fingerprint:
                raise ValueError("Idempotency-Key was already used with a different assessment configuration.")
            return _assessment_dict(existing), False
        component_rows = lookup_db.scalars(
            select(SBOMComponent)
            .where(SBOMComponent.sbom_import_id == import_id)
            .order_by(SBOMComponent.ordinal)
        ).all()
        components = [
            {
                "name": row.name.strip().lower(),
                "source_name": row.name,
                "version": row.version.strip(),
                "source_version": row.version,
                "purl": row.purl,
            }
            for row in component_rows
        ]
        component_ids = [row.id for row in component_rows]

    started_at = datetime.now(timezone.utc)
    findings, osv_enrichment = await sbom.scan_with_metadata_async(
        components, include_component_index=True
    )
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or not isinstance(finding.get("component_index"), int)
            or isinstance(finding.get("component_index"), bool)
            or finding["component_index"] < 0
            or finding["component_index"] >= len(components)
            or not isinstance(finding.get("vuln_id"), str)
            or not finding["vuln_id"].strip()
            or not isinstance(finding.get("severity"), str)
            or not isinstance(finding.get("source"), str)
            or not finding["source"].strip()
        ):
            raise RuntimeError("Scanner returned a malformed or unscoped finding.")
    findings, intelligence_enrichment = await intelligence.enrich_findings(findings)
    provider_statuses = [
        osv_enrichment.get("status", "incomplete"),
        intelligence_enrichment.get("kev", {}).get("status", "incomplete"),
        intelligence_enrichment.get("epss", {}).get("status", "incomplete"),
    ]
    if "incomplete" in provider_statuses:
        assessment_status = "incomplete"
    elif "complete" in provider_statuses:
        assessment_status = "complete"
    else:
        assessment_status = "disabled"
    enrichment = {
        "status": assessment_status,
        "osv": osv_enrichment,
        "intelligence": intelligence_enrichment,
    }
    completed_at = datetime.now(timezone.utc)

    # External enrichment is complete before the audit writer transaction starts.
    audit.acquire_chain_lock(db)
    imported = db.get(SBOMImport, import_id)
    if imported is None or imported.status != "accepted":
        raise LookupError("Accepted SBOM import not found")
    existing = db.scalars(
        select(SBOMAssessment).where(
            SBOMAssessment.sbom_import_id == import_id,
            SBOMAssessment.request_key_hash == request_key_hash,
        )
    ).first()
    if existing is not None:
        if existing.source_fingerprint != source_fingerprint:
            db.rollback()
            raise ValueError("Idempotency-Key was already used with a different assessment configuration.")
        result = _assessment_dict(existing)
        db.rollback()
        return result, False

    status = assessment_status
    if status not in {"disabled", "complete", "incomplete"}:
        status = "incomplete"
        enrichment = {**enrichment, "status": status, "invalid_status": True}

    assessment = SBOMAssessment(
        sbom_import_id=import_id,
        request_key_hash=request_key_hash,
        source_fingerprint=source_fingerprint,
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        component_count=len(components),
        finding_count=len(findings),
        enrichment_metadata=enrichment,
    )
    db.add(assessment)
    try:
        db.flush()
        for finding in findings:
            if not isinstance(finding, dict):
                raise RuntimeError("Scanner returned a malformed finding.")
            index = finding.get("component_index")
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or index < 0
                or index >= len(component_ids)
                or not isinstance(finding.get("vuln_id"), str)
                or not finding["vuln_id"].strip()
                or not isinstance(finding.get("severity"), str)
                or not isinstance(finding.get("source"), str)
                or not finding["source"].strip()
            ):
                raise RuntimeError("Scanner returned a malformed or unscoped finding.")
            db.add(
                SBOMAssessmentFinding(
                    assessment_id=assessment.id,
                    sbom_component_id=component_ids[index],
                    vuln_id=finding["vuln_id"],
                    severity=finding["severity"],
                    fixed_in=finding.get("fixed_in"),
                    source=finding["source"],
                    intelligence=finding.get("intelligence", {}),
                    applicability=applicability.assess_finding(
                        finding, components[index]
                    ),
                )
            )
        audit.record(
            db,
            actor,
            "sbom.assessment",
            str(assessment.id),
            {
                "sbom_import_id": import_id,
                "status": status,
                "component_count": len(components),
                "finding_count": len(findings),
                "source_fingerprint": source_fingerprint,
            },
        )
        db.commit()
        db.refresh(assessment)
        return _assessment_dict(assessment), True
    except Exception:
        db.rollback()
        raise
