import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import AuditEntry, utcnow

GENESIS = "0" * 64


def _digest(prev: str, ts: str, actor: str, action: str, entity: str, payload: dict) -> str:
    body = json.dumps([prev, ts, actor, action, entity, payload], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def record(db: Session, actor: str, action: str, entity: str, payload: dict) -> None:
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
