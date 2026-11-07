import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from time import sleep
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session

from app import audit
from app.audit import record, verify
from app.db import AuditChainState, AuditEntry, Device
from app.db import engine as application_engine

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
