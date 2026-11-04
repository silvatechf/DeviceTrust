from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session

from app.audit import record, verify
from app.db import AuditEntry, Base


def _database(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'audit-boundaries.db'}")
    Base.metadata.create_all(engine)
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
