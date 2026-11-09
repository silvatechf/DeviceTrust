"""Immutable evidence manifests bound to exact vulnerability decision revisions."""

import hashlib
import hmac
from datetime import timezone

import rfc8785
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, evidence_artifacts
from .db import (
    DecisionApproval,
    DecisionEvidenceManifest,
    EvidenceArtifact,
    SignedDecision,
    VulnerabilityDecision,
    utcnow,
)

MANIFEST_VERSION = "devicetrust.decision-evidence-manifest.v1"


class EvidenceManifestConflict(RuntimeError):
    """Raised when a decision already has a different immutable evidence manifest."""


class EvidenceManifestIntegrityError(RuntimeError):
    """Raised when a stored evidence manifest fails integrity validation."""


def _utc_iso(value):
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _manifest_payload(decision: VulnerabilityDecision, artifacts: list[EvidenceArtifact]) -> dict:
    return {
        "manifest_version": MANIFEST_VERSION,
        "decision_id": decision.id,
        "assessment_finding_id": decision.assessment_finding_id,
        "decision_revision": decision.revision,
        "decision_created_at": _utc_iso(decision.created_at),
        "artifacts": [
            {
                "artifact_id": item.id,
                "observation_id": item.observation_id,
                "sha256": item.sha256,
                "byte_size": item.byte_size,
                "media_type": item.media_type,
                "recorded_at": _utc_iso(item.created_at),
            }
            for item in sorted(artifacts, key=lambda artifact: artifact.id)
        ],
    }


def create_manifest(
    db: Session,
    *,
    decision_id: int,
    principal_id: str,
    artifact_ids: list[str],
) -> tuple[DecisionEvidenceManifest, bool]:
    decision = db.get(VulnerabilityDecision, decision_id)
    if decision is None:
        raise LookupError("Decision not found")
    if decision.principal_id != principal_id:
        raise PermissionError("Only the decision author can bind its evidence manifest")
    if not artifact_ids or len(artifact_ids) > 10 or len(set(artifact_ids)) != len(artifact_ids):
        raise ValueError("Evidence manifest requires 1 to 10 unique artifact IDs")
    if not set(artifact_ids).issubset(set(decision.evidence_references or [])):
        raise ValueError("Every artifact ID must already be referenced by the decision")

    existing = db.scalar(
        select(DecisionEvidenceManifest).where(
            DecisionEvidenceManifest.decision_id == decision_id
        )
    )
    if existing is not None:
        if set(existing.artifact_ids or []) == set(artifact_ids):
            return existing, False
        raise EvidenceManifestConflict(
            "Decision already has an immutable evidence manifest"
        )

    # A manifest must be established before any author signature or approval.
    if db.scalar(select(SignedDecision.id).where(SignedDecision.decision_id == decision_id)) is not None:
        raise EvidenceManifestConflict("Evidence manifest must be bound before decision signing")
    if db.scalar(select(DecisionApproval.id).where(DecisionApproval.decision_id == decision_id)) is not None:
        raise EvidenceManifestConflict("Evidence manifest must be bound before independent approval")

    artifacts = db.scalars(
        select(EvidenceArtifact).where(EvidenceArtifact.id.in_(artifact_ids))
    ).all()
    if len(artifacts) != len(artifact_ids):
        raise LookupError("One or more evidence artifacts were not found")
    for artifact in artifacts:
        if not evidence_artifacts.verify_artifact(artifact)["valid"]:
            raise ValueError("Evidence artifact integrity verification failed")

    payload = _manifest_payload(decision, artifacts)
    canonical = rfc8785.dumps(payload)
    digest = hashlib.sha256(canonical).hexdigest()
    item = DecisionEvidenceManifest(
        decision_id=decision_id,
        manifest_version=MANIFEST_VERSION,
        manifest_payload=payload,
        manifest_sha256=digest,
        artifact_ids=sorted(artifact_ids),
        created_by=principal_id,
        created_at=utcnow(),
    )
    db.add(item)
    db.flush()
    audit.record(
        db,
        f"principal:{principal_id}",
        "vulnerability.decision.evidence_manifest_bind",
        str(decision_id),
        {
            "decision_id": decision_id,
            "manifest_sha256": digest,
            "artifact_count": len(artifacts),
            "artifact_ids": sorted(artifact_ids),
        },
    )
    return item, True


def get_manifest(db: Session, decision_id: int) -> dict | None:
    item = db.scalar(
        select(DecisionEvidenceManifest).where(
            DecisionEvidenceManifest.decision_id == decision_id
        )
    )
    if item is None:
        return None
    try:
        if (
            item.manifest_version != MANIFEST_VERSION
            or not isinstance(item.artifact_ids, list)
            or not isinstance(item.manifest_sha256, str)
            or len(item.manifest_sha256) != 64
        ):
            raise ValueError("Stored evidence manifest metadata is invalid")
        canonical = rfc8785.dumps(item.manifest_payload)
        actual_digest = hashlib.sha256(canonical).hexdigest()
        digest_valid = hmac.compare_digest(actual_digest, item.manifest_sha256)
        decision = db.get(VulnerabilityDecision, decision_id)
        artifacts = db.scalars(
            select(EvidenceArtifact).where(
                EvidenceArtifact.id.in_(item.artifact_ids)
            )
        ).all()
    except (TypeError, ValueError, OverflowError):
        raise EvidenceManifestIntegrityError(
            "Stored decision evidence manifest integrity validation failed"
        ) from None
    artifact_map = {artifact.id: artifact for artifact in artifacts}
    artifact_integrity_valid = (
        decision is not None
        and len(artifact_map) == len(item.artifact_ids or [])
        and all(evidence_artifacts.verify_artifact(artifact)["valid"] for artifact in artifacts)
    )
    if artifact_integrity_valid:
        current_payload = _manifest_payload(
            decision, [artifact_map[artifact_id] for artifact_id in item.artifact_ids]
        )
        artifact_integrity_valid = rfc8785.dumps(current_payload) == canonical
    return {
        "decision_id": item.decision_id,
        "manifest_version": item.manifest_version,
        "manifest": item.manifest_payload,
        "manifest_sha256": item.manifest_sha256,
        "actual_manifest_sha256": actual_digest,
        "manifest_digest_valid": digest_valid,
        "artifact_integrity_valid": artifact_integrity_valid,
        "integrity_valid": digest_valid and artifact_integrity_valid,
        "artifact_ids": item.artifact_ids,
        "created_by": item.created_by,
        "created_at": item.created_at,
    }


def current_manifest_digest(db: Session, decision_id: int) -> str | None:
    result = get_manifest(db, decision_id)
    if result is None:
        return None
    if not result["integrity_valid"]:
        raise EvidenceManifestIntegrityError(
            "Stored decision evidence manifest integrity validation failed"
        )
    return result["manifest_sha256"]
