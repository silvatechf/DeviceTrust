import asyncio
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from time import sleep
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, inspect, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app import audit, identity, product_sbom, vulnerability_decisions
from app.audit import record, verify
from app.db import (
    APICredential,
    AuditChainState,
    AuditEntry,
    Device,
    Principal,
    Product,
    ProductFinding,
    ProductRelease,
    SBOMAssessment,
    SBOMAssessmentFinding,
    SBOMComponent,
    SBOMImport,
    VulnerabilityDecision,
)
from app.db import engine as application_engine
from app.main import app

pytestmark = pytest.mark.skipif(
    not os.getenv("DATABASE_URL", "").startswith(("postgresql://", "postgresql+psycopg://")),
    reason="PostgreSQL integration test requires DATABASE_URL to use PostgreSQL",
)


def test_device_survives_database_engine_disposal():
    device_id = f"PG-TEST-{uuid4().hex[:12]}"
    with Session(application_engine) as session:
        session.add(
            Device(
                device_id=device_id,
                manufacturer="Integration Test",
                model="Persistence Fixture",
                firmware_version="1.0.0",
                security={},
            )
        )
        session.commit()

    application_engine.dispose()
    verification_engine = create_engine(os.environ["DATABASE_URL"])
    try:
        with Session(verification_engine) as session:
            device = session.scalar(select(Device).where(Device.device_id == device_id))
            assert device is not None
            assert device.manufacturer == "Integration Test"
    finally:
        with Session(verification_engine) as session:
            session.execute(delete(Device).where(Device.device_id == device_id))
            session.commit()
        verification_engine.dispose()


def test_audit_chain_serializes_concurrent_postgres_writers(monkeypatch):
    writer_count = 8
    barrier = Barrier(writer_count)
    original_digest = audit._digest

    def slow_digest(prev, ts, actor, action, entity, payload):
        sleep(0.02)
        return original_digest(prev, ts, actor, action, entity, payload)

    monkeypatch.setattr(audit, "_digest", slow_digest)

    with Session(application_engine) as session:
        state = session.get(AuditChainState, 1)
        assert state is not None
        version_before = state.version

    def write_event(index):
        with Session(application_engine) as session:
            barrier.wait(timeout=10)
            record(
                session,
                "concurrency-test",
                "audit.concurrent",
                f"POSTGRES-{index}",
                {"sequence": index},
            )
            session.commit()

    with ThreadPoolExecutor(max_workers=writer_count) as executor:
        list(executor.map(write_event, range(writer_count)))

    with Session(application_engine) as session:
        assert verify(session)["valid"] is True
        state = session.get(AuditChainState, 1)
        assert state is not None
        assert state.version == version_before + writer_count
        assert (
            session.query(AuditEntry)
            .filter_by(actor="concurrency-test", action="audit.concurrent")
            .count()
            == writer_count
        )



def test_concurrent_product_api_writes_keep_domain_and_audit_atomic_postgres(
    monkeypatch,
):
    writer_count = 8
    barrier = Barrier(writer_count)
    original_digest = audit._digest

    def slow_digest(prev, ts, actor, action, entity, payload):
        sleep(0.02)
        return original_digest(prev, ts, actor, action, entity, payload)

    monkeypatch.setattr(audit, "_digest", slow_digest)

    with Session(application_engine) as session:
        state = session.get(AuditChainState, 1)
        assert state is not None
        version_before = state.version

    def create_product(index):
        with TestClient(app) as api:
            barrier.wait(timeout=10)
            return api.post(
                "/products",
                json={
                    "manufacturer": "Concurrent PostgreSQL API Test",
                    "product_name": f"concurrent-{uuid4().hex}-{index}",
                },
                headers={"X-API-Key": "test-key"},
            )

    with ThreadPoolExecutor(max_workers=writer_count) as executor:
        responses = list(executor.map(create_product, range(writer_count)))

    assert all(response.status_code == 201 for response in responses)
    product_ids = {response.json()["id"] for response in responses}
    assert len(product_ids) == writer_count

    with Session(application_engine) as session:
        products = session.scalars(
            select(Product).where(Product.id.in_(product_ids))
        ).all()
        entries = session.scalars(
            select(AuditEntry).where(
                AuditEntry.actor == "api-key",
                AuditEntry.action == "product.create",
                AuditEntry.entity.in_([str(item) for item in product_ids]),
            )
        ).all()
        state = session.get(AuditChainState, 1)
        assert state is not None
        assert {product.id for product in products} == product_ids
        assert {entry.entity for entry in entries} == {
            str(product_id) for product_id in product_ids
        }
        assert len(entries) == writer_count
        assert state.version == version_before + writer_count
        assert verify(session)["valid"] is True


def test_audit_chain_migration_upgrade_downgrade_round_trip_postgres(
    monkeypatch,
):
    database_name = f"devicetrust_migration_{uuid4().hex}"
    admin_engine = create_engine(os.environ["DATABASE_URL"])
    target_engine = None
    database_created = False

    try:
        with admin_engine.connect().execution_options(
            isolation_level="AUTOCOMMIT"
        ) as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')
        database_created = True

        target_url = make_url(os.environ["DATABASE_URL"]).set(
            database=database_name
        )
        target_engine = create_engine(target_url)
        monkeypatch.setenv(
            "DATABASE_URL",
            target_url.render_as_string(hide_password=False),
        )
        config = Config("alembic.ini")
        config.set_main_option(
            "sqlalchemy.url",
            target_url.render_as_string(hide_password=False),
        )

        command.upgrade(config, "0002_persistent_sbom")
        assert not inspect(target_engine).has_table("audit_chain_state")

        command.upgrade(config, "head")
        assert inspect(target_engine).has_table("audit_chain_state")
        assert inspect(target_engine).has_table("sbom_assessments")
        assert inspect(target_engine).has_table("sbom_assessment_findings")
        assert inspect(target_engine).has_table("principals")
        assert inspect(target_engine).has_table("api_credentials")
        assert inspect(target_engine).has_table("vulnerability_decisions")
        decision_columns = {
            column["name"]
            for column in inspect(target_engine).get_columns("vulnerability_decisions")
        }
        assert {"request_key_hash", "request_fingerprint"}.issubset(decision_columns)
        assessment_finding_columns = {
            column["name"]: column
            for column in inspect(target_engine).get_columns(
                "sbom_assessment_findings"
            )
        }
        assert "intelligence" in assessment_finding_columns
        assert "applicability" in assessment_finding_columns
        assert assessment_finding_columns["applicability"]["nullable"] is False
        assert "bom_metadata" in {
            column["name"] for column in inspect(target_engine).get_columns("sbom_imports")
        }
        assert "bom_ref" in {
            column["name"] for column in inspect(target_engine).get_columns("sbom_components")
        }
        with target_engine.connect() as connection:
            assert connection.scalar(
                text("SELECT version FROM audit_chain_state WHERE id = 1")
            ) == 0
            assert connection.scalar(
                text("SELECT COUNT(*) FROM audit_chain_state")
            ) == 1
        command.check(config)

        command.downgrade(config, "0008_sbom_reference_preservation")
        assert not inspect(target_engine).has_table("vulnerability_decisions")
        command.upgrade(config, "head")
        assert inspect(target_engine).has_table("vulnerability_decisions")

        command.downgrade(config, "0007_sbom_finding_applicability")
        assert not inspect(target_engine).has_table("vulnerability_decisions")
        assert "bom_metadata" not in {
            column["name"] for column in inspect(target_engine).get_columns("sbom_imports")
        }
        assert "bom_ref" not in {
            column["name"] for column in inspect(target_engine).get_columns("sbom_components")
        }
        command.upgrade(config, "head")
        assert "bom_metadata" in {
            column["name"] for column in inspect(target_engine).get_columns("sbom_imports")
        }
        assert "bom_ref" in {
            column["name"] for column in inspect(target_engine).get_columns("sbom_components")
        }

        command.downgrade(config, "0006_identity_access")
        assert not inspect(target_engine).has_table("vulnerability_decisions")
        assert "applicability" not in {
            column["name"]
            for column in inspect(target_engine).get_columns("sbom_assessment_findings")
        }
        command.upgrade(config, "head")
        assert "applicability" in {
            column["name"]
            for column in inspect(target_engine).get_columns("sbom_assessment_findings")
        }

        command.downgrade(config, "0002_persistent_sbom")
        assert not inspect(target_engine).has_table("audit_chain_state")
        assert not inspect(target_engine).has_table("sbom_assessments")
        assert not inspect(target_engine).has_table("sbom_assessment_findings")
        assert not inspect(target_engine).has_table("api_credentials")
        assert not inspect(target_engine).has_table("principals")
        assert not inspect(target_engine).has_table("vulnerability_decisions")

        command.upgrade(config, "head")
        assert inspect(target_engine).has_table("audit_chain_state")
        assert inspect(target_engine).has_table("principals")
        assert inspect(target_engine).has_table("api_credentials")
        with target_engine.connect() as connection:
            assert connection.scalar(
                text("SELECT version FROM audit_chain_state WHERE id = 1")
            ) == 0
    finally:
        if target_engine is not None:
            target_engine.dispose()
        if database_created:
            with admin_engine.connect().execution_options(
                isolation_level="AUTOCOMMIT"
            ) as connection:
                connection.exec_driver_sql(
                    f'DROP DATABASE IF EXISTS "{database_name}" WITH (FORCE)'
                )
        admin_engine.dispose()



def test_failed_product_api_write_rolls_back_and_releases_postgres_lock(
    monkeypatch,
):
    product_name = f"postgres-rollback-{uuid4().hex}"
    original_record = audit.record

    with Session(application_engine) as session:
        state = session.get(AuditChainState, 1)
        assert state is not None
        version_before = state.version
        audit_count_before = session.query(AuditEntry).count()

    def fail_after_audit_flush(session, actor, action, entity, payload):
        original_record(session, actor, action, entity, payload)
        raise RuntimeError("injected PostgreSQL failure after audit flush")

    monkeypatch.setattr(audit, "record", fail_after_audit_flush)
    with TestClient(app, raise_server_exceptions=False) as api:
        failed = api.post(
            "/products",
            json={
                "manufacturer": "PostgreSQL Rollback Test",
                "product_name": product_name,
            },
            headers={"X-API-Key": "test-key"},
        )
    assert failed.status_code == 500

    monkeypatch.setattr(audit, "record", original_record)
    with Session(application_engine) as session:
        state = session.get(AuditChainState, 1)
        assert state is not None
        assert state.version == version_before
        assert (
            session.query(Product).filter_by(product_name=product_name).count()
            == 0
        )
        assert session.query(AuditEntry).count() == audit_count_before

    with TestClient(app) as api:
        recovered = api.post(
            "/products",
            json={
                "manufacturer": "PostgreSQL Rollback Test",
                "product_name": product_name,
            },
            headers={"X-API-Key": "test-key"},
        )
    assert recovered.status_code == 201

    with Session(application_engine) as session:
        state = session.get(AuditChainState, 1)
        assert state is not None
        assert state.version == version_before + 1
        assert (
            session.query(Product).filter_by(product_name=product_name).count()
            == 1
        )
        assert (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "product.create",
                AuditEntry.entity == str(recovered.json()["id"]),
            )
            .count()
            == 1
        )
        assert verify(session)["valid"] is True
def test_product_sbom_records_survive_database_engine_disposal():
    suffix = uuid4().hex[:12]
    digest = uuid4().hex * 2

    with Session(application_engine) as session:
        product = Product(
            manufacturer="PostgreSQL Integration",
            product_name=f"SBOM Persistence {suffix}",
        )
        session.add(product)
        session.flush()

        release = ProductRelease(product_id=product.id, version="1.0.0")
        session.add(release)
        session.flush()

        imported = SBOMImport(
            product_release_id=release.id,
            format="CycloneDX",
            spec_version="1.5",
            source_type="manual",
            content_sha256=digest,
            parser_version="0.4.0",
            status="accepted",
            component_count=1,
            validation_summary={"valid": True, "component_count": 1},
            bom_metadata={
                "serial_number": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                "version": 2,
                "version_explicit": True,
                "metadata_component": None,
            },
        )
        session.add(imported)
        session.flush()

        component = SBOMComponent(
            sbom_import_id=imported.id,
            ordinal=0,
            name="Example Library",
            version="1.0.0",
            purl="pkg:generic/example-library@1.0.0",
            bom_ref="example-library-ref",
        )
        session.add(component)
        session.flush()

        finding = ProductFinding(
            sbom_component_id=component.id,
            vuln_id="DT-PG-TEST-0001",
            severity="high",
            fixed_in="1.0.1",
            source="synthetic",
        )
        session.add(finding)
        session.commit()

        product_id = product.id
        release_id = release.id
        import_id = imported.id
        component_id = component.id
        finding_id = finding.id

    application_engine.dispose()
    verification_engine = create_engine(os.environ["DATABASE_URL"])
    try:
        with Session(verification_engine) as session:
            persisted_product = session.get(Product, product_id)
            persisted_release = session.get(ProductRelease, release_id)
            persisted_import = session.get(SBOMImport, import_id)
            persisted_component = session.get(SBOMComponent, component_id)
            persisted_finding = session.get(ProductFinding, finding_id)

            assert persisted_product is not None
            assert persisted_release is not None
            assert persisted_import is not None
            assert persisted_import.content_sha256 == digest
            assert persisted_import.bom_metadata["version"] == 2
            assert persisted_component is not None
            assert persisted_component.sbom_import_id == import_id
            assert persisted_component.bom_ref == "example-library-ref"
            assert persisted_finding is not None
            assert persisted_finding.sbom_component_id == component_id
    finally:
        with Session(verification_engine) as session:
            session.execute(delete(ProductFinding).where(ProductFinding.id == finding_id))
            session.execute(delete(SBOMComponent).where(SBOMComponent.id == component_id))
            session.execute(delete(SBOMImport).where(SBOMImport.id == import_id))
            session.execute(delete(ProductRelease).where(ProductRelease.id == release_id))
            session.execute(delete(Product).where(Product.id == product_id))
            session.commit()
        verification_engine.dispose()


def test_product_sbom_import_rolls_back_on_postgres_audit_failure(monkeypatch):
    suffix = uuid4().hex[:12]
    raw_document = (
        Path(__file__).parent.parent / "samples" / "sensor_sbom.json"
    ).read_bytes()
    document = json.loads(raw_document)

    with Session(application_engine) as session:
        product = Product(
            manufacturer="PostgreSQL Integration",
            product_name=f"SBOM Rollback {suffix}",
        )
        session.add(product)
        session.flush()

        release = ProductRelease(product_id=product.id, version="1.0.0")
        session.add(release)
        session.commit()
        release_id = release.id

        audit_count_before = session.query(AuditEntry).filter_by(
            action="sbom.product_import"
        ).count()

        original_record = product_sbom.audit.record

        def fail_import_audit(db, actor, action, entity, payload):
            result = original_record(db, actor, action, entity, payload)
            if action == "sbom.product_import":
                raise RuntimeError("injected PostgreSQL audit append failure")
            return result

        monkeypatch.setattr(product_sbom.audit, "record", fail_import_audit)

        with pytest.raises(RuntimeError, match="injected PostgreSQL audit append failure"):
            asyncio.run(product_sbom.import_cyclonedx(
                session,
                "postgres-integration",
                release_id,
                raw_document,
                document,
                "manual",
                None,
            ))

        assert session.query(SBOMImport).filter_by(
            product_release_id=release_id
        ).count() == 0
        assert (
            session.query(SBOMComponent)
            .join(SBOMImport)
            .filter(SBOMImport.product_release_id == release_id)
            .count()
            == 0
        )
        assert (
            session.query(ProductFinding)
            .join(SBOMComponent)
            .join(SBOMImport)
            .filter(SBOMImport.product_release_id == release_id)
            .count()
            == 0
        )
        assert (
            session.query(AuditEntry).filter_by(action="sbom.product_import").count()
            == audit_count_before
        )

        session.execute(delete(ProductRelease).where(ProductRelease.id == release_id))
        session.execute(delete(Product).where(Product.id == product.id))
        session.commit()



def test_versioned_sbom_assessment_survives_postgres_engine_disposal(monkeypatch):
    suffix = uuid4().hex
    actor = f"assessment-pg-{suffix[:12]}"
    digest = hashlib.sha256(suffix.encode()).hexdigest()

    async def fake_scan(components, *, include_component_index=False):
        assert include_component_index is True
        return [{
            "component_index": 0,
            "vuln_id": "CVE-2099-9001",
            "severity": "high",
            "fixed_in": "1.0.1",
            "source": "local-demo",
        }], {"status": "disabled", "source": "osv"}

    monkeypatch.setattr(product_sbom.sbom, "scan_with_metadata_async", fake_scan)
    monkeypatch.delenv("DEVICETRUST_OSV", raising=False)

    with Session(application_engine) as session:
        product = Product(
            manufacturer="PostgreSQL Assessment Test",
            product_name=f"Assessment {suffix}",
        )
        session.add(product)
        session.flush()
        release = ProductRelease(product_id=product.id, version="1.0.0")
        session.add(release)
        session.flush()
        imported = SBOMImport(
            product_release_id=release.id,
            format="CycloneDX",
            spec_version="1.5",
            source_type="manual",
            content_sha256=digest,
            parser_version="0.3.0",
            status="accepted",
            component_count=1,
            validation_summary={"valid": True},
        )
        session.add(imported)
        session.flush()
        component = SBOMComponent(
            sbom_import_id=imported.id,
            ordinal=0,
            name="Example Library",
            version="1.0.0",
            purl="pkg:generic/example-library@1.0.0",
        )
        session.add(component)
        session.commit()
        product_id = product.id
        release_id = release.id
        import_id = imported.id
        component_id = component.id

        assessment, created = asyncio.run(
            product_sbom.reassess_import(
                session, actor, import_id, f"request-{suffix}"
            )
        )
        assert created is True
        assessment_id = assessment["id"]

    application_engine.dispose()
    verification_engine = create_engine(os.environ["DATABASE_URL"])
    try:
        with Session(verification_engine) as session:
            persisted = session.get(SBOMAssessment, assessment_id)
            findings = session.scalars(
                select(SBOMAssessmentFinding).where(
                    SBOMAssessmentFinding.assessment_id == assessment_id
                )
            ).all()
            assert persisted is not None
            assert persisted.status == "disabled"
            assert persisted.component_count == 1
            assert persisted.finding_count == 1
            assert len(findings) == 1
            assert findings[0].sbom_component_id == component_id
            assert findings[0].vuln_id == "CVE-2099-9001"
            assert findings[0].applicability["status"] == "synthetic_candidate"
            assert verify(session)["valid"] is True
    finally:
        with Session(verification_engine) as session:
            session.execute(
                delete(SBOMAssessmentFinding).where(
                    SBOMAssessmentFinding.assessment_id == assessment_id
                )
            )
            session.execute(
                delete(SBOMAssessment).where(SBOMAssessment.id == assessment_id)
            )
            session.execute(delete(SBOMComponent).where(SBOMComponent.id == component_id))
            session.execute(delete(SBOMImport).where(SBOMImport.id == import_id))
            session.execute(delete(ProductRelease).where(ProductRelease.id == release_id))
            session.execute(delete(Product).where(Product.id == product_id))
            session.commit()
        verification_engine.dispose()


def test_managed_api_credentials_authenticate_and_revoke_postgres():
    with Session(application_engine) as session:
        principal, credential, token = identity.create_principal(
            session,
            name="PostgreSQL identity integration",
            kind="service",
            scopes={"inventory:read"},
        )
        principal_id = principal.id
        credential_id = credential.id
        session.commit()

    try:
        with Session(application_engine) as session:
            authenticated = identity.authenticate(session, token)
            assert authenticated is not None
            assert authenticated.principal_id == principal_id
            assert authenticated.scopes == frozenset({"inventory:read"})
            stored = session.get(APICredential, credential_id)
            assert stored is not None
            assert token not in stored.token_digest

            identity.revoke_credential(session, credential_id)
            session.commit()

        with Session(application_engine) as session:
            assert identity.authenticate(session, token) is None
    finally:
        with Session(application_engine) as session:
            session.query(APICredential).filter_by(id=credential_id).delete()
            session.query(Principal).filter_by(id=principal_id).delete()
            session.commit()



def test_review_decisions_persist_and_link_revisions_postgres():
    suffix = uuid4().hex
    principal_id = str(uuid4())
    finding_id = None
    product_id = release_id = import_id = component_id = assessment_id = None

    with Session(application_engine) as session:
        principal = Principal(
            id=principal_id,
            name=f"PostgreSQL reviewer {suffix[:8]}",
            kind="operator",
            status="active",
        )
        product = Product(
            manufacturer="PostgreSQL VEX Integration",
            product_name=f"Reviewed Decision {suffix[:8]}",
        )
        session.add_all([principal, product])
        session.flush()
        product_id = product.id

        release = ProductRelease(product_id=product.id, version="9.1.0")
        session.add(release)
        session.flush()
        release_id = release.id

        imported = SBOMImport(
            product_release_id=release.id,
            format="CycloneDX",
            spec_version="1.5",
            source_type="manual",
            content_sha256=hashlib.sha256(suffix.encode()).hexdigest(),
            parser_version="0.4.0",
            status="accepted",
            component_count=1,
            validation_summary={"valid": True},
            bom_metadata={"serial_number": None, "version": 1, "version_explicit": False, "metadata_component": None},
        )
        session.add(imported)
        session.flush()
        import_id = imported.id

        component = SBOMComponent(
            sbom_import_id=imported.id,
            ordinal=0,
            name="libexample",
            version="1.0.0",
            purl="pkg:generic/libexample@1.0.0",
            bom_ref=f"component-{suffix[:8]}",
        )
        session.add(component)
        session.flush()
        component_id = component.id

        assessment = SBOMAssessment(
            sbom_import_id=imported.id,
            request_key_hash=hashlib.sha256(f"request-{suffix}".encode()).hexdigest(),
            source_fingerprint=hashlib.sha256(f"source-{suffix}".encode()).hexdigest(),
            status="complete",
            component_count=1,
            finding_count=1,
            enrichment_metadata={},
        )
        session.add(assessment)
        session.flush()
        assessment_id = assessment.id

        finding = SBOMAssessmentFinding(
            assessment_id=assessment.id,
            sbom_component_id=component.id,
            vuln_id="CVE-2026-54321",
            severity="high",
            fixed_in="1.0.1",
            source="osv",
            intelligence={},
            applicability={"status": "osv_reported_affected"},
        )
        session.add(finding)
        session.flush()
        finding_id = finding.id
        session.commit()

    try:
        with Session(application_engine) as session:
            audit.acquire_chain_lock(session)
            first, first_created = vulnerability_decisions.create_decision(
                session,
                finding_id=finding_id,
                principal_id=principal_id,
                state="in_triage",
                justification=None,
                detail="The vendor impact statement is being reviewed.",
                evidence_references=[],
                responses=[],
                idempotency_key="postgres-review-001",
            )
            session.commit()

        with Session(application_engine) as session:
            audit.acquire_chain_lock(session)
            retried, retry_created = vulnerability_decisions.create_decision(
                session,
                finding_id=finding_id,
                principal_id=principal_id,
                state="in_triage",
                justification=None,
                detail="The vendor impact statement is being reviewed.",
                evidence_references=[],
                responses=[],
                idempotency_key="postgres-review-001",
            )
            session.commit()

        with Session(application_engine) as session:
            audit.acquire_chain_lock(session)
            second, second_created = vulnerability_decisions.create_decision(
                session,
                finding_id=finding_id,
                principal_id=principal_id,
                state="not_affected",
                justification="code_not_reachable",
                detail="Runtime call-path analysis confirms the vulnerable function is not invoked.",
                evidence_references=["evidence://postgres/review-001"],
                responses=["will_not_fix"],
                idempotency_key="postgres-review-002",
            )
            session.commit()

        assert first_created is True
        assert retry_created is False
        assert retried["id"] == first["id"]
        assert second_created is True
        assert first["revision"] == 1
        assert second["revision"] == 2
        assert second["supersedes_id"] == first["id"]

        with Session(application_engine) as session:
            rows = session.scalars(
                select(VulnerabilityDecision)
                .where(VulnerabilityDecision.assessment_finding_id == finding_id)
                .order_by(VulnerabilityDecision.revision)
            ).all()
            assert [row.revision for row in rows] == [1, 2]
            assert audit.verify(session)["valid"] is True
    finally:
        with Session(application_engine) as session:
            session.execute(delete(VulnerabilityDecision).where(VulnerabilityDecision.assessment_finding_id == finding_id))
            session.execute(delete(SBOMAssessmentFinding).where(SBOMAssessmentFinding.id == finding_id))
            session.execute(delete(SBOMAssessment).where(SBOMAssessment.id == assessment_id))
            session.execute(delete(SBOMComponent).where(SBOMComponent.id == component_id))
            session.execute(delete(SBOMImport).where(SBOMImport.id == import_id))
            session.execute(delete(ProductRelease).where(ProductRelease.id == release_id))
            session.execute(delete(Product).where(Product.id == product_id))
            session.execute(delete(Principal).where(Principal.id == principal_id))
            session.commit()
