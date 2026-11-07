from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from time import sleep

import pytest
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session

from app import audit
from app.audit import record, verify
from app.db import AuditChainState, AuditEntry, Base


def _database(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'audit-boundaries.db'}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(AuditChainState(id=1, version=0))
        db.commit()
    return engine


def _record_events(db, count=3):
    for index in range(count):
        record(db, "test", "device.update", "DEVICE-1", {"sequence": index})
        db.commit()


def test_audit_chain_detects_deletion_of_an_interior_entry(tmp_path):
    engine = _database(tmp_path)
    try:
        with Session(engine) as db:
            _record_events(db)
            db.execute(delete(AuditEntry).where(AuditEntry.id == 2))
            db.commit()

            result = verify(db)

            assert result["valid"] is False
            assert result["broken_at_id"] == 3
            assert result["entries"] == 1
    finally:
        engine.dispose()


def test_audit_chain_cannot_detect_deletion_of_a_final_suffix_without_checkpoint(tmp_path):
    engine = _database(tmp_path)
    try:
        with Session(engine) as db:
            _record_events(db)
            db.execute(delete(AuditEntry).where(AuditEntry.id >= 2))
            db.commit()

            result = verify(db)

            assert result == {"valid": True, "entries": 1}
    finally:
        engine.dispose()



def test_audit_chain_serializes_concurrent_sqlite_writers(tmp_path, monkeypatch):
    engine = _database(tmp_path)
    writer_count = 8
    barrier = Barrier(writer_count)
    original_digest = audit._digest

    def slow_digest(prev, ts, actor, action, entity, payload):
        sleep(0.02)
        return original_digest(prev, ts, actor, action, entity, payload)

    monkeypatch.setattr(audit, "_digest", slow_digest)

    def write_event(index):
        with Session(engine) as db:
            barrier.wait(timeout=10)
            record(db, "concurrency-test", "audit.concurrent", "SQLITE", {"sequence": index})
            db.commit()

    try:
        with ThreadPoolExecutor(max_workers=writer_count) as executor:
            list(executor.map(write_event, range(writer_count)))

        with Session(engine) as db:
            assert verify(db) == {"valid": True, "entries": writer_count}
            state = db.get(AuditChainState, 1)
            assert state is not None
            assert state.version == writer_count
            assert (
                db.query(AuditEntry)
                .filter_by(actor="concurrency-test", action="audit.concurrent")
                .count()
                == writer_count
            )
    finally:
        engine.dispose()



def test_audit_append_fails_closed_without_migrated_chain_state(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'missing-chain-state.db'}")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            with pytest.raises(RuntimeError, match="Audit chain state is missing"):
                record(db, "test", "device.create", "DEVICE-1", {"id": 1})
            assert db.query(AuditEntry).count() == 0
    finally:
        engine.dispose()


def test_audit_chain_state_and_entry_roll_back_together(tmp_path):
    engine = _database(tmp_path)
    try:
        with Session(engine) as db:
            state = db.get(AuditChainState, 1)
            assert state is not None
            version_before = state.version

        with Session(engine) as db:
            record(db, "test", "device.create", "ROLLBACK-001", {"id": 1})
            db.rollback()

        with Session(engine) as db:
            state = db.get(AuditChainState, 1)
            assert state is not None
            assert state.version == version_before
            assert db.query(AuditEntry).count() == 0
    finally:
        engine.dispose()
