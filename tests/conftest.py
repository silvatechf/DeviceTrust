import os
import tempfile
from pathlib import Path

os.environ.setdefault(
    "DATABASE_URL",
    f"sqlite:///{Path(tempfile.mkdtemp()) / 'test.db'}",
)
os.environ.setdefault("DEVICETRUST_API_KEY", "test-key")

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

H = {"X-API-Key": "test-key"}


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    config = Config("alembic.ini")
    command.upgrade(config, "head")


@pytest.fixture(scope="session")
def client(migrated_database):
    with TestClient(app) as client:
        yield client
