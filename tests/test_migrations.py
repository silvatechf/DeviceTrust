from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_initial_migration_can_upgrade_and_downgrade(tmp_path: Path):
    database_url = f"sqlite:///{tmp_path / 'migration-test.db'}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")
    engine = create_engine(database_url)
    try:
        tables = set(inspect(engine).get_table_names())
        assert {"alembic_version", "devices", "evidence_observations", "vulnerabilities", "audit_log"} <= tables
        command.check(config)

        command.downgrade(config, "base")
        assert "devices" not in inspect(engine).get_table_names()
    finally:
        engine.dispose()
