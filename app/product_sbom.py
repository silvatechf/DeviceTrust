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

PARSER_VERSION = "0.2.0"


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
    findings_by_component: dict[tuple[str, str], list[dict]] = {}
    for finding in sbom.scan(components):
        key = (finding["component"], finding["version"])
        findings_by_component.setdefault(key, []).append(finding)

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
                version=component["version"],
                purl=component["purl"],
            )
            db.add(occurrence)
            db.flush()

            key = (component["name"], component["version"])
            for finding in findings_by_component.get(key, []):
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
