import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session

from app.db import Device, engine as application_engine

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
