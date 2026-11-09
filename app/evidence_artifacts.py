"""Bounded, content-addressed evidence artifact persistence and verification."""

import hashlib
import hmac
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .db import EvidenceArtifact, EvidenceObservation, utcnow

MAX_ARTIFACT_BYTES = 5 * 1024 * 1024
ALLOWED_MEDIA_TYPES = frozenset(
    {
        "application/octet-stream",
        "application/json",
        "application/pdf",
        "text/plain",
    }
)


def create_artifact(
    db: Session,
    *,
    observation_id: int,
    content: bytes,
    media_type: str,
    actor: str,
) -> tuple[EvidenceArtifact, bool]:
    if not content or len(content) > MAX_ARTIFACT_BYTES:
        raise ValueError("Evidence artifact must contain 1 to 5242880 bytes")
    normalized_media_type = media_type.strip().lower()
    if normalized_media_type not in ALLOWED_MEDIA_TYPES:
        raise ValueError("Evidence artifact media type is not allowed")

    observation = db.get(EvidenceObservation, observation_id)
    if observation is None:
        raise LookupError("Evidence observation not found")

    digest = hashlib.sha256(content).hexdigest()
    existing = db.scalar(
        select(EvidenceArtifact).where(
            EvidenceArtifact.observation_id == observation_id,
            EvidenceArtifact.sha256 == digest,
            EvidenceArtifact.media_type == normalized_media_type,
        )
    )
    if existing is not None:
        if not hmac.compare_digest(existing.content, content):
            raise RuntimeError("Stored evidence artifact digest collision detected")
        return existing, False

    artifact = EvidenceArtifact(
        id=str(uuid4()),
        observation_id=observation_id,
        sha256=digest,
        byte_size=len(content),
        media_type=normalized_media_type,
        content=content,
        uploaded_by=actor,
        created_at=utcnow(),
    )
    db.add(artifact)
    db.flush()
    audit.record(
        db,
        actor,
        "evidence.artifact.attach",
        f"observation:{observation_id}",
        {
            "artifact_id": artifact.id,
            "sha256": digest,
            "byte_size": len(content),
            "media_type": normalized_media_type,
        },
    )
    return artifact, True


def verify_artifact(artifact: EvidenceArtifact) -> dict:
    actual_size = len(artifact.content)
    actual_digest = hashlib.sha256(artifact.content).hexdigest()
    digest_valid = hmac.compare_digest(actual_digest, artifact.sha256)
    size_valid = actual_size == artifact.byte_size
    return {
        "artifact_id": artifact.id,
        "observation_id": artifact.observation_id,
        "expected_sha256": artifact.sha256,
        "actual_sha256": actual_digest,
        "expected_byte_size": artifact.byte_size,
        "actual_byte_size": actual_size,
        "digest_valid": digest_valid,
        "size_valid": size_valid,
        "valid": digest_valid and size_valid,
    }


def artifact_metadata(
    artifact: EvidenceArtifact, *, include_integrity: bool = False
) -> dict:
    result = {
        "id": artifact.id,
        "observation_id": artifact.observation_id,
        "sha256": artifact.sha256,
        "byte_size": artifact.byte_size,
        "media_type": artifact.media_type,
        "uploaded_by": artifact.uploaded_by,
        "created_at": artifact.created_at,
    }
    if include_integrity:
        result["integrity_valid"] = verify_artifact(artifact)["valid"]
    return result
