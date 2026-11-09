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

        command.upgrade(config, "head")
        assert inspect(engine).has_table("audit_chain_state")
        assert inspect(engine).has_table("principals")
        assert inspect(engine).has_table("api_credentials")
        assert inspect(engine).has_table("vulnerability_decisions")
        decision_columns = {
            column["name"]: column
            for column in inspect(engine).get_columns("vulnerability_decisions")
        }
        assert {"assessment_finding_id", "principal_id", "revision", "supersedes_id", "state", "justification", "detail", "evidence_references", "responses", "created_at"}.issubset(decision_columns)
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
        command.upgrade(config, "head")
        assert inspect(engine).has_table("vulnerability_decisions")

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
