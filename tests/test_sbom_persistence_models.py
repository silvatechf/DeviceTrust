import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import Base, Product, ProductRelease, SBOMComponent, SBOMImport


def _accepted_import(db: Session, digest: str = "a" * 64) -> SBOMImport:
    product = Product(manufacturer="Acme", product_name="Sensor")
    db.add(product)
    db.flush()
    release = ProductRelease(product_id=product.id, version="1.0")
    db.add(release)
    db.flush()
    imported = SBOMImport(
        product_release_id=release.id,
        format="CycloneDX",
        spec_version="1.5",
        source_type="manual",
        content_sha256=digest,
        parser_version="0.2.0",
        status="accepted",
        component_count=0,
        validation_summary={},
    )
    db.add(imported)
    db.flush()
    return imported


def test_sbom_import_digest_is_unique_per_release_and_format():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        imported = _accepted_import(db)
        duplicate = SBOMImport(
            product_release_id=imported.product_release_id,
            format=imported.format,
            spec_version="1.5",
            source_type="manual",
            content_sha256=imported.content_sha256,
            parser_version="0.2.0",
            status="accepted",
            component_count=0,
            validation_summary={},
        )
        db.add(duplicate)
        with pytest.raises(IntegrityError):
            db.flush()


def test_component_ordinal_is_unique_within_import():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        imported = _accepted_import(db)
        db.add_all([
            SBOMComponent(
                sbom_import_id=imported.id,
                ordinal=0,
                name="OpenSSL",
                version="1.1.1",
                purl="pkg:generic/openssl@1.1.1",
            ),
            SBOMComponent(
                sbom_import_id=imported.id,
                ordinal=0,
                name="OpenSSL",
                version="1.1.1",
                purl="pkg:generic/openssl@1.1.1",
            ),
        ])
        with pytest.raises(IntegrityError):
            db.flush()
