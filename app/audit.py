import hashlib
import json

from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from .db import AuditChainState, AuditEntry, utcnow

GENESIS = "0" * 64


def acquire_chain_lock(db: Session) -> None:
    """Serialize audit appends within the caller's domain transaction.

    SQLite requires an IMMEDIATE transaction before any request reads. PostgreSQL
    serializes writers by updating the singleton state row, whose row lock is held
    until the surrounding transaction commits or rolls back.
    """
    transaction = db.get_transaction()
    if transaction is not None and db.info.get("audit_chain_locked_tx") is transaction:
        return

    dialect = db.get_bind().dialect.name
    if dialect == "sqlite":
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
    elif dialect == "postgresql":
        db.execute(text("SET LOCAL lock_timeout = '10s'"))

    result = db.execute(
        update(AuditChainState)
        .where(AuditChainState.id == 1)
        .values(version=AuditChainState.version + 1)
    )
    if result.rowcount != 1:
        raise RuntimeError(
            "Audit chain state is missing; apply database migrations before writing audit events."
        )

    db.info["audit_chain_locked_tx"] = db.get_transaction()


def _digest(prev: str, ts: str, actor: str, action: str, entity: str, payload: dict) -> str:
    body = json.dumps([prev, ts, actor, action, entity, payload], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def record(db: Session, actor: str, action: str, entity: str, payload: dict) -> None:
    acquire_chain_lock(db)
    last = db.scalars(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(1)).first()
    prev = last.hash if last else GENESIS
    ts = utcnow().isoformat()
    db.add(AuditEntry(ts=ts, actor=actor, action=action, entity=entity, payload=payload,
                      prev_hash=prev, hash=_digest(prev, ts, actor, action, entity, payload)))
    db.flush()


def verify(db: Session) -> dict:
    prev = GENESIS
    count = 0
    for entry in db.scalars(select(AuditEntry).order_by(AuditEntry.id)):
        if entry.prev_hash != prev or entry.hash != _digest(
            prev, entry.ts, entry.actor, entry.action, entry.entity, entry.payload
        ):
            return {"valid": False, "broken_at_id": entry.id, "entries": count}
        prev, count = entry.hash, count + 1
    return {"valid": True, "entries": count}
