from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def test_audit_chain_migration_upgrade_downgrade_round_trip(tmp_path: Path, monkeypatch):
    database_url = f"sqlite:///{tmp_path / 'audit-migration-test.db'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    engine = create_engine(database_url)

    try:
        command.upgrade(config, "0002_persistent_sbom")
        assert not inspect(engine).has_table("audit_chain_state")
        assert not inspect(engine).has_table("evidence_artifacts")
        assert not inspect(engine).has_table("decision_evidence_manifests")

        command.upgrade(config, "head")
        assert inspect(engine).has_table("audit_chain_state")
        assert inspect(engine).has_table("principals")
        assert inspect(engine).has_table("api_credentials")
        assert inspect(engine).has_table("vulnerability_decisions")
        assert inspect(engine).has_table("signing_keys")
        assert inspect(engine).has_table("signed_decisions")
        assert inspect(engine).has_table("decision_approvals")
        assert inspect(engine).has_table("evidence_artifacts")
        assert inspect(engine).has_table("decision_evidence_manifests")
        manifest_columns = {
            column["name"]: column
            for column in inspect(engine).get_columns("decision_evidence_manifests")
        }
        assert {
            "id", "decision_id", "manifest_version", "manifest_payload",
            "manifest_sha256", "artifact_ids", "created_by", "created_at",
        }.issubset(manifest_columns)
        manifest_checks = inspect(engine).get_check_constraints(
            "decision_evidence_manifests"
        )
        assert any(
            check["name"] == "ck_decision_evidence_manifest_version"
            for check in manifest_checks
        )
        artifact_columns = {
            column["name"]: column
            for column in inspect(engine).get_columns("evidence_artifacts")
        }
        assert {
            "id", "observation_id", "sha256", "byte_size", "media_type",
            "content", "uploaded_by", "created_at",
        }.issubset(artifact_columns)
        assert artifact_columns["content"]["nullable"] is False
        artifact_checks = inspect(engine).get_check_constraints("evidence_artifacts")
        size_check = next(
            check["sqltext"] for check in artifact_checks
            if check["name"] == "ck_evidence_artifact_size"
        )
        assert "5242880" in size_check
        signing_key_checks = inspect(engine).get_check_constraints("signing_keys")
        purpose_check = next(
            check["sqltext"] for check in signing_key_checks
            if check["name"] == "ck_signing_key_purpose"
        )
        assert "decision-approval" in purpose_check
        decision_columns = {
            column["name"]: column
            for column in inspect(engine).get_columns("vulnerability_decisions")
        }
        assert {
            "assessment_finding_id",
            "principal_id",
            "revision",
            "request_key_hash",
            "request_fingerprint",
            "supersedes_id",
            "state",
            "justification",
            "detail",
            "evidence_references",
            "responses",
            "created_at",
        }.issubset(decision_columns)
        finding_columns = {
            column["name"]: column
            for column in inspect(engine).get_columns("sbom_assessment_findings")
        }
        assert "intelligence" in finding_columns
        assert finding_columns["intelligence"]["nullable"] is False
        assert "applicability" in finding_columns
        assert finding_columns["applicability"]["nullable"] is False
        import_columns = {
            column["name"]: column
            for column in inspect(engine).get_columns("sbom_imports")
        }
        component_columns = {
            column["name"]: column
            for column in inspect(engine).get_columns("sbom_components")
        }
        assert import_columns["bom_metadata"]["nullable"] is False
        assert component_columns["bom_ref"]["nullable"] is True
        with engine.connect() as connection:
            assert connection.scalar(
                text("SELECT version FROM audit_chain_state WHERE id = 1")
            ) == 0
            assert connection.scalar(
                text("SELECT COUNT(*) FROM audit_chain_state")
            ) == 1
        command.check(config)

        command.downgrade(config, "0008_sbom_reference_preservation")
        assert not inspect(engine).has_table("vulnerability_decisions")
        assert not inspect(engine).has_table("signing_keys")
        assert not inspect(engine).has_table("signed_decisions")
        assert not inspect(engine).has_table("decision_approvals")
        assert not inspect(engine).has_table("evidence_artifacts")
        assert not inspect(engine).has_table("decision_evidence_manifests")
        command.upgrade(config, "head")
        assert inspect(engine).has_table("vulnerability_decisions")
        assert inspect(engine).has_table("signing_keys")
        assert inspect(engine).has_table("signed_decisions")
        assert inspect(engine).has_table("decision_approvals")
        assert inspect(engine).has_table("evidence_artifacts")
        assert inspect(engine).has_table("decision_evidence_manifests")

        command.downgrade(config, "0007_sbom_finding_applicability")
        assert not inspect(engine).has_table("vulnerability_decisions")
        assert "bom_metadata" not in {
            column["name"] for column in inspect(engine).get_columns("sbom_imports")
        }
        assert "bom_ref" not in {
            column["name"] for column in inspect(engine).get_columns("sbom_components")
        }
        command.upgrade(config, "head")
        assert "bom_metadata" in {
            column["name"] for column in inspect(engine).get_columns("sbom_imports")
        }
        assert "bom_ref" in {
            column["name"] for column in inspect(engine).get_columns("sbom_components")
        }

        command.downgrade(config, "0006_identity_access")
        assert not inspect(engine).has_table("vulnerability_decisions")
        assert "applicability" not in {
            column["name"]
            for column in inspect(engine).get_columns("sbom_assessment_findings")
        }
        command.upgrade(config, "head")
        assert "applicability" in {
            column["name"]
            for column in inspect(engine).get_columns("sbom_assessment_findings")
        }

        command.downgrade(config, "0002_persistent_sbom")
        assert not inspect(engine).has_table("api_credentials")
        assert not inspect(engine).has_table("principals")
        assert not inspect(engine).has_table("vulnerability_decisions")
        assert not inspect(engine).has_table("audit_chain_state")

        command.upgrade(config, "head")
        assert inspect(engine).has_table("audit_chain_state")
        assert inspect(engine).has_table("principals")
        assert inspect(engine).has_table("api_credentials")
        with engine.connect() as connection:
            assert connection.scalar(
                text("SELECT version FROM audit_chain_state WHERE id = 1")
            ) == 0
    finally:
        engine.dispose()
