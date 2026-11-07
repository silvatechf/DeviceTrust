"""Transactional persistence for accepted CycloneDX SBOM imports."""

import hashlib

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import audit, sbom
from .db import (
    Product,
    ProductFinding,
    ProductRelease,
    SBOMComponent,
    SBOMImport,
)

PARSER_VERSION = "0.3.0"


def create_product(
    db: Session,
    actor: str,
    manufacturer: str,
    product_name: str,
    external_reference: str | None,
) -> Product:
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


def import_cyclonedx(
    db: Session,
    actor: str,
    release_id: int,
    raw_document: bytes,
    document: dict,
    source_type: str,
    source_reference: str | None,
) -> tuple[SBOMImport, bool]:
    if db.get(ProductRelease, release_id) is None:
        raise LookupError("Product release not found")

    components = sbom.parse_cyclonedx(document)
    findings_by_component: dict[int, list[dict]] = {}
    for finding in sbom.scan(components, include_component_index=True):
        component_index = finding["component_index"]
        findings_by_component.setdefault(component_index, []).append(finding)

    digest = hashlib.sha256(raw_document).hexdigest()
    existing = db.scalars(
        select(SBOMImport).where(
            SBOMImport.product_release_id == release_id,
            SBOMImport.format == "CycloneDX",
            SBOMImport.content_sha256 == digest,
        )
    ).first()
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
        validation_summary={
            "valid": True,
            "component_count": len(components),
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
    }


def compare_imports(
    db: Session,
    release_id: int,
    from_import_id: int,
    to_import_id: int,
) -> dict:
    """Compare two accepted imports without mutating stored SBOM evidence.

    Package URLs are compared without their version segment so a version change
    remains a match. Missing or repeated package identities are never guessed.
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
    version_changed = []
    metadata_changed = []
    ambiguous = []
    unchanged = 0

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
        if old_item.version != new_item.version:
            version_changed.append({
                "identity": identity,
                "previous": _component_snapshot(old_item),
                "current": _component_snapshot(new_item),
            })
        elif old_item.name != new_item.name:
            metadata_changed.append({
                "identity": identity,
                "previous": _component_snapshot(old_item),
                "current": _component_snapshot(new_item),
            })
        else:
            unchanged += 1

    return {
        "product_release_id": release_id,
        "from_import_id": from_import_id,
        "to_import_id": to_import_id,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "version_changed": len(version_changed),
            "metadata_changed": len(metadata_changed),
            "unchanged": unchanged,
            "ambiguous": len(ambiguous),
            "unidentified_previous": len(previous_unidentified),
            "unidentified_current": len(current_unidentified),
        },
        "added": added,
        "removed": removed,
        "version_changed": version_changed,
        "metadata_changed": metadata_changed,
        "ambiguous": ambiguous,
        "unidentified": {
            "previous": previous_unidentified,
            "current": current_unidentified,
        },
    }
