"""Independent Ed25519 approvals for immutable vulnerability decision revisions."""

import base64
import binascii
import hashlib
from datetime import datetime, timedelta, timezone

import rfc8785
from cryptography.exceptions import InvalidSignature
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, decision_signatures
from .db import DecisionApproval, Principal, SigningKey, VulnerabilityDecision, utcnow

POLICY_VERSION = "devicetrust.approval-policy.v1"
ENVELOPE_VERSION = "devicetrust.decision-approval.v1"
DOMAIN_SEPARATOR = b"DeviceTrust\x00DecisionApproval\x00v1\x00"
APPROVAL_WINDOW = timedelta(minutes=30)
FUTURE_CLOCK_SKEW = timedelta(minutes=1)
REQUIRED_APPROVALS = 1


class ApprovalConflict(RuntimeError):
    """Raised when an approval key already has a different immutable record."""


class ApprovalTrustStoreError(RuntimeError):
    """Raised when registered approval key material cannot be trusted."""


def _utc(value: datetime, *, require_aware: bool = False) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        if require_aware:
            raise ValueError("approval timestamp must be timezone-aware")
        # SQLite does not preserve timezone metadata for DateTime columns.
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utc_iso(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _decode_signature(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("signature must be valid standard Base64") from None
    if len(raw) != 64:
        raise ValueError("Ed25519 signatures must contain exactly 64 bytes")
    return raw


def _current_revision(db: Session, decision: VulnerabilityDecision) -> bool:
    latest = db.scalar(
        select(VulnerabilityDecision)
        .where(VulnerabilityDecision.assessment_finding_id == decision.assessment_finding_id)
        .order_by(VulnerabilityDecision.revision.desc())
        .limit(1)
    )
    return latest is not None and latest.id == decision.id


def _trusted_author_signature(db: Session, decision_id: int) -> bool:
    result = decision_signatures.get_decision_signature(db, decision_id)
    return result is not None and result["trust_valid"] is True


def _active_approval_key(
    db: Session, *, key_id: str, principal_id: str
) -> SigningKey:
    principal = db.get(Principal, principal_id)
    if principal is None or principal.status != "active" or principal.kind != "operator":
        raise PermissionError("An active operator principal is required for independent approval")
    key = db.get(SigningKey, key_id)
    if key is None:
        raise LookupError("Approval signing key not found")
    if key.principal_id != principal_id or key.purpose != "decision-approval":
        raise PermissionError("Approval key is not bound to this operator and approval purpose")
    if key.revoked_at is not None:
        raise PermissionError("Approval signing key has been revoked")
    if key.expires_at is not None:
        expiry = key.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= utcnow():
            raise PermissionError("Approval signing key has expired")
    try:
        decision_signatures._registered_public_key(key)
    except ValueError:
        raise ApprovalTrustStoreError("Registered approval key integrity validation failed") from None
    return key


def approval_envelope(
    decision: VulnerabilityDecision,
    *,
    decision_digest: str,
    approver_principal_id: str,
    key_id: str,
    key_fingerprint: str,
    approved_at: datetime,
    policy_version: str = POLICY_VERSION,
) -> bytes:
    payload = {
        "envelope_version": ENVELOPE_VERSION,
        "decision_id": decision.id,
        "assessment_finding_id": decision.assessment_finding_id,
        "revision": decision.revision,
        "decision_envelope_sha256": decision_digest,
        "approval_purpose": "independent-second-person-review",
        "approver_principal_id": approver_principal_id,
        "signing_key_id": key_id,
        "signing_key_fingerprint": key_fingerprint,
        "policy_version": policy_version,
        "approved_at": _utc_iso(approved_at),
    }
    return DOMAIN_SEPARATOR + rfc8785.dumps(payload)


def get_approval_payload(
    db: Session, *, decision_id: int, principal_id: str, key_id: str
) -> dict:
    decision = db.get(VulnerabilityDecision, decision_id)
    if decision is None:
        raise LookupError("Decision not found")
    if principal_id == decision.principal_id:
        raise PermissionError("The decision author cannot approve their own decision")
    if not _current_revision(db, decision):
        raise PermissionError("Only the current decision revision can receive approval")
    key = _active_approval_key(db, key_id=key_id, principal_id=principal_id)
    if not _trusted_author_signature(db, decision_id):
        raise PermissionError("A currently trusted author signature is required before approval")

    decision_digest = hashlib.sha256(decision_signatures.signing_envelope(decision)).hexdigest()
    approved_at = utcnow()
    envelope = approval_envelope(
        decision,
        decision_digest=decision_digest,
        approver_principal_id=principal_id,
        key_id=key.id,
        key_fingerprint=key.fingerprint,
        approved_at=approved_at,
    )
    return {
        "decision_id": decision_id,
        "revision": decision.revision,
        "approver_principal_id": principal_id,
        "key_id": key.id,
        "key_fingerprint": key.fingerprint,
        "algorithm": key.algorithm,
        "policy_version": POLICY_VERSION,
        "envelope_version": ENVELOPE_VERSION,
        "decision_envelope_sha256": decision_digest,
        "envelope_sha256": hashlib.sha256(envelope).hexdigest(),
        "approved_at": _utc_iso(approved_at),
        "approval_expires_at": _utc_iso(approved_at + APPROVAL_WINDOW),
        "signing_payload_base64": base64.b64encode(envelope).decode("ascii"),
    }


def approve_decision(
    db: Session,
    *,
    decision_id: int,
    principal_id: str,
    key_id: str,
    approved_at: datetime,
    signature_b64: str,
) -> tuple[dict, bool]:
    decision = db.get(VulnerabilityDecision, decision_id)
    if decision is None:
        raise LookupError("Decision not found")
    if principal_id == decision.principal_id:
        raise PermissionError("The decision author cannot approve their own decision")
    if not _current_revision(db, decision):
        raise PermissionError("Only the current decision revision can receive approval")
    key = _active_approval_key(db, key_id=key_id, principal_id=principal_id)
    if not _trusted_author_signature(db, decision_id):
        raise PermissionError("A currently trusted author signature is required before approval")

    approved_at = _utc(approved_at, require_aware=True)
    now = utcnow()
    if approved_at > now + FUTURE_CLOCK_SKEW or approved_at < now - APPROVAL_WINDOW:
        raise ValueError("approval payload has expired; request a new approval payload")

    decision_digest = hashlib.sha256(decision_signatures.signing_envelope(decision)).hexdigest()
    envelope = approval_envelope(
        decision,
        decision_digest=decision_digest,
        approver_principal_id=principal_id,
        key_id=key.id,
        key_fingerprint=key.fingerprint,
        approved_at=approved_at,
    )
    signature = _decode_signature(signature_b64)
    public_key = decision_signatures._registered_public_key(key)
    try:
        public_key.verify(signature, envelope)
    except (InvalidSignature, TypeError):
        raise ValueError("detached approval signature does not match the approval envelope") from None

    envelope_digest = hashlib.sha256(envelope).hexdigest()
    existing = db.scalar(
        select(DecisionApproval).where(
            DecisionApproval.decision_id == decision_id,
            DecisionApproval.signing_key_id == key_id,
        )
    )
    if existing is not None:
        if (
            existing.signature_b64 == signature_b64
            and existing.envelope_sha256 == envelope_digest
            and _utc_iso(existing.approved_at) == _utc_iso(approved_at)
        ):
            return _approval_dict(existing, key, decision=decision, envelope=envelope), False
        raise ApprovalConflict("decision already has an immutable approval from this key")

    item = DecisionApproval(
        decision_id=decision_id,
        signing_key_id=key_id,
        principal_id=principal_id,
        policy_version=POLICY_VERSION,
        envelope_version=ENVELOPE_VERSION,
        decision_envelope_sha256=decision_digest,
        envelope_sha256=envelope_digest,
        signature_b64=signature_b64,
        approved_at=approved_at,
        recorded_at=now,
    )
    db.add(item)
    db.flush()
    audit.record(
        db,
        f"principal:{principal_id}",
        "vulnerability.decision.approve",
        str(decision_id),
        {
            "decision_id": decision_id,
            "approval_id": item.id,
            "approver_principal_id": principal_id,
            "key_id": key_id,
            "key_fingerprint": key.fingerprint,
            "policy_version": POLICY_VERSION,
            "decision_envelope_sha256": decision_digest,
            "approval_envelope_sha256": envelope_digest,
        },
    )
    return _approval_dict(item, key, decision=decision, envelope=envelope), True


def _approval_dict(
    item: DecisionApproval,
    key: SigningKey,
    *,
    decision: VulnerabilityDecision | None = None,
    envelope: bytes | None = None,
) -> dict:
    result = {
        "id": item.id,
        "decision_id": item.decision_id,
        "approver_principal_id": item.principal_id,
        "key_id": item.signing_key_id,
        "key_fingerprint": key.fingerprint,
        "algorithm": key.algorithm,
        "policy_version": item.policy_version,
        "envelope_version": item.envelope_version,
        "decision_envelope_sha256": item.decision_envelope_sha256,
        "envelope_sha256": item.envelope_sha256,
        "signature": item.signature_b64,
        "public_key_pem": key.public_key_pem,
        "approved_at": _utc_iso(item.approved_at),
        "recorded_at": _utc_iso(item.recorded_at),
    }
    if decision is not None:
        result["assessment_finding_id"] = decision.assessment_finding_id
        result["revision"] = decision.revision
        result["approval_purpose"] = "independent-second-person-review"
    if envelope is not None:
        result["approval_payload_base64"] = base64.b64encode(envelope).decode("ascii")
    return result


def get_decision_approval(db: Session, decision_id: int) -> dict:
    decision = db.get(VulnerabilityDecision, decision_id)
    if decision is None:
        raise LookupError("Decision not found")
    current_digest = hashlib.sha256(decision_signatures.signing_envelope(decision)).hexdigest()
    current_revision = _current_revision(db, decision)
    author_signature_trusted = _trusted_author_signature(db, decision_id)
    items = db.scalars(
        select(DecisionApproval)
        .where(DecisionApproval.decision_id == decision_id)
        .order_by(DecisionApproval.id)
    ).all()

    approvals = []
    eligible_approvers = set()
    for item in items:
        key = db.get(SigningKey, item.signing_key_id)
        if key is None:
            approvals.append(
                {
                    "id": item.id,
                    "decision_id": item.decision_id,
                    "approver_principal_id": item.principal_id,
                    "key_id": item.signing_key_id,
                    "signature_valid": False,
                    "trust_valid": False,
                    "eligible_for_current_revision": False,
                    "current_key_status": "missing",
                    "current_principal_status": "missing",
                }
            )
            continue

        signature_valid = False
        envelope = None
        try:
            envelope = approval_envelope(
                decision,
                decision_digest=item.decision_envelope_sha256,
                approver_principal_id=item.principal_id,
                key_id=key.id,
                key_fingerprint=key.fingerprint,
                approved_at=item.approved_at,
                policy_version=item.policy_version,
            )
            signature_valid = (
                item.envelope_version == ENVELOPE_VERSION
                and item.envelope_sha256 == hashlib.sha256(envelope).hexdigest()
                and item.decision_envelope_sha256 == current_digest
            )
            if signature_valid:
                decision_signatures._registered_public_key(key).verify(
                    _decode_signature(item.signature_b64), envelope
                )
        except (ValueError, InvalidSignature, TypeError):
            signature_valid = False

        key_status = "revoked" if key.revoked_at is not None else "active"
        if key.expires_at is not None:
            expiry = key.expires_at
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= utcnow():
                key_status = "expired"
        principal = db.get(Principal, key.principal_id)
        principal_status = (
            "active"
            if (
                principal is not None
                and principal.status == "active"
                and principal.kind == "operator"
                and key.principal_id == item.principal_id
                and item.principal_id != decision.principal_id
                and key.purpose == "decision-approval"
            )
            else "disabled_or_invalid"
        )
        trust_valid = (
            signature_valid
            and key_status == "active"
            and principal_status == "active"
        )
        eligible = (
            trust_valid
            and current_revision
            and author_signature_trusted
            and item.policy_version == POLICY_VERSION
        )
        if eligible:
            eligible_approvers.add(item.principal_id)
        approvals.append(
            {
                **_approval_dict(item, key, decision=decision, envelope=envelope),
                "signature_valid": signature_valid,
                "trust_valid": trust_valid,
                "eligible_for_current_revision": eligible,
                "current_key_status": key_status,
                "current_principal_status": principal_status,
            }
        )

    approval_count = len(eligible_approvers)
    policy_satisfied = (
        current_revision
        and author_signature_trusted
        and approval_count >= REQUIRED_APPROVALS
    )
    return {
        "decision_id": decision_id,
        "revision": decision.revision,
        "policy_version": POLICY_VERSION,
        "required_approvals": REQUIRED_APPROVALS,
        "current_revision": current_revision,
        "current_decision_envelope_sha256": current_digest,
        "author_signature_trusted": author_signature_trusted,
        "approvals": approvals,
        "valid_approver_count": approval_count,
        "approval_policy_satisfied": policy_satisfied,
    }
