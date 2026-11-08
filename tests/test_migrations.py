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
        assert "intelligence" in {
            column["name"] for column in inspect(engine).get_columns(
                "sbom_assessment_findings"
            )
        }
        with engine.connect() as connection:
            assert connection.scalar(
                text("SELECT version FROM audit_chain_state WHERE id = 1")
            ) == 0
            assert connection.scalar(
                text("SELECT COUNT(*) FROM audit_chain_state")
            ) == 1
        command.check(config)

        command.downgrade(config, "0002_persistent_sbom")
        assert not inspect(engine).has_table("audit_chain_state")

        command.upgrade(config, "head")
        assert inspect(engine).has_table("audit_chain_state")
        with engine.connect() as connection:
            assert connection.scalar(
                text("SELECT version FROM audit_chain_state WHERE id = 1")
            ) == 0
    finally:
        engine.dispose()
