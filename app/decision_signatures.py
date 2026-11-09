"""Detached Ed25519 signatures for immutable vulnerability decisions."""

import base64
import binascii
import hashlib
import hmac
from datetime import timezone
from uuid import uuid4

import rfc8785

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .db import Principal, SigningKey, SignedDecision, VulnerabilityDecision, utcnow

ENVELOPE_VERSION = "devicetrust.decision-signature.v1"
DOMAIN_SEPARATOR = b"DeviceTrust\x00DecisionSignature\x00v1\x00"


class SignatureConflict(RuntimeError):
    """Raised when a decision already has a different detached signature."""


def _utc_iso(value):
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def signing_envelope(decision: VulnerabilityDecision) -> bytes:
    """Return canonical, domain-separated bytes for one immutable decision."""
    payload = {
        "envelope_version": ENVELOPE_VERSION,
        "decision_id": decision.id,
        "assessment_finding_id": decision.assessment_finding_id,
        "principal_id": decision.principal_id,
        "revision": decision.revision,
        "supersedes_id": decision.supersedes_id,
        "state": decision.state,
        "justification": decision.justification,
        "detail": decision.detail,
        "evidence_references": list(decision.evidence_references or []),
        "responses": list(decision.responses or []),
        "created_at": _utc_iso(decision.created_at),
    }
    canonical = rfc8785.dumps(payload)
    return DOMAIN_SEPARATOR + canonical


def _registered_public_key(key: SigningKey) -> Ed25519PublicKey:
    if key.algorithm != "Ed25519":
        raise ValueError("registered signing key algorithm is not supported")
    try:
        public_key = serialization.load_pem_public_key(key.public_key_pem.encode("ascii"))
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ValueError("registered public key material is invalid") from None
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("registered signing key is not Ed25519")
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), key.fingerprint):
        raise ValueError("registered public key fingerprint does not match key material")
    return public_key


def _decode_signature(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("signature must be valid standard Base64") from None
    if len(raw) != 64:
        raise ValueError("Ed25519 signatures must contain exactly 64 bytes")
    return raw


def register_public_key(
    db: Session, *, principal_id: str, public_key_pem: bytes, expires_at=None
) -> SigningKey:
    principal = db.get(Principal, principal_id)
    if principal is None or principal.status != "active":
        raise LookupError("Active principal not found")
    if principal.kind != "operator":
        raise PermissionError("Only operator principals can register decision-signing keys")
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ValueError("public key must be a valid PEM-encoded Ed25519 public key") from None
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("only Ed25519 public keys are supported")
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = hashlib.sha256(raw).hexdigest()
    existing = db.scalar(select(SigningKey).where(SigningKey.fingerprint == fingerprint))
    if existing is not None:
        if existing.principal_id != principal_id or existing.purpose != "decision-signing":
            raise ValueError("public key fingerprint is already registered to another trust binding")
        if existing.revoked_at is not None:
            raise ValueError("revoked public keys cannot be reactivated")
        return existing
    now = utcnow()
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            raise ValueError("public key expiry must be in the future")
    item = SigningKey(
        id=str(uuid4()),
        principal_id=principal_id,
        purpose="decision-signing",
        algorithm="Ed25519",
        public_key_pem=public_key_pem.decode("ascii"),
        fingerprint=fingerprint,
        created_at=now,
        expires_at=expires_at,
        revoked_at=None,
    )
    db.add(item)
    db.flush()
    audit.record(
        db,
        "offline-admin",
        "identity.signing_key_register",
        item.id,
        {"principal_id": principal_id, "key_id": item.id, "fingerprint": fingerprint, "purpose": item.purpose},
    )
    return item


def revoke_public_key(db: Session, key_id: str) -> SigningKey:
    item = db.get(SigningKey, key_id)
    if item is None:
        raise LookupError("Signing key not found")
    if item.revoked_at is None:
        item.revoked_at = utcnow()
        db.flush()
        audit.record(
            db,
            "offline-admin",
            "identity.signing_key_revoke",
            item.id,
            {"key_id": item.id, "fingerprint": item.fingerprint},
        )
    return item


def get_signing_payload(db: Session, *, decision_id: int, principal_id: str, key_id: str) -> dict:
    decision = db.get(VulnerabilityDecision, decision_id)
    if decision is None:
        raise LookupError("Decision not found")
    if decision.principal_id != principal_id:
        raise PermissionError("Only the decision author can request its signing payload")
    key = db.get(SigningKey, key_id)
    if key is None:
        raise LookupError("Signing key not found")
    if key.principal_id != principal_id or key.purpose != "decision-signing":
        raise PermissionError("Signing key is not bound to this operator and purpose")
    if key.revoked_at is not None:
        raise PermissionError("Signing key has been revoked")
    if key.expires_at is not None:
        expiry = key.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= utcnow():
            raise PermissionError("Signing key has expired")
    principal = db.get(Principal, principal_id)
    if principal is None or principal.status != "active" or principal.kind != "operator":
        raise PermissionError("An active operator principal is required")
    _registered_public_key(key)
    envelope = signing_envelope(decision)
    return {
        "decision_id": decision_id,
        "key_id": key.id,
        "key_fingerprint": key.fingerprint,
        "algorithm": key.algorithm,
        "envelope_version": ENVELOPE_VERSION,
        "envelope_sha256": hashlib.sha256(envelope).hexdigest(),
        "signing_payload_base64": base64.b64encode(envelope).decode("ascii"),
    }


def sign_decision(
    db: Session, *, decision_id: int, principal_id: str, key_id: str, signature_b64: str
) -> tuple[dict, bool]:
    decision = db.get(VulnerabilityDecision, decision_id)
    if decision is None:
        raise LookupError("Decision not found")
    if decision.principal_id != principal_id:
        raise PermissionError("Only the decision author can sign this decision")
    principal = db.get(Principal, principal_id)
    if principal is None or principal.status != "active" or principal.kind != "operator":
        raise PermissionError("An active operator principal is required")
    key = db.get(SigningKey, key_id)
    if key is None:
        raise LookupError("Signing key not found")
    if key.principal_id != principal_id or key.purpose != "decision-signing":
        raise PermissionError("Signing key is not bound to this operator and purpose")
    if key.revoked_at is not None:
        raise PermissionError("Signing key has been revoked")
    if key.expires_at is not None:
        expiry = key.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= utcnow():
            raise PermissionError("Signing key has expired")
    signature = _decode_signature(signature_b64)
    envelope = signing_envelope(decision)
    envelope_digest = hashlib.sha256(envelope).hexdigest()
    public_key = _registered_public_key(key)
    try:
        public_key.verify(signature, envelope)
    except (InvalidSignature, TypeError):
        raise ValueError("detached signature does not match the decision envelope") from None

    existing = db.scalar(select(SignedDecision).where(SignedDecision.decision_id == decision_id))
    if existing is not None:
        if (
            existing.signing_key_id == key_id
            and existing.signature_b64 == signature_b64
            and existing.envelope_sha256 == envelope_digest
        ):
            return _signature_dict(existing, key), False
        raise SignatureConflict("decision already has a different immutable signature")

    item = SignedDecision(
        decision_id=decision_id,
        signing_key_id=key_id,
        principal_id=principal_id,
        envelope_version=ENVELOPE_VERSION,
        envelope_sha256=envelope_digest,
        signature_b64=signature_b64,
        verified_at=utcnow(),
    )
    db.add(item)
    db.flush()
    audit.record(
        db,
        f"principal:{principal_id}",
        "vulnerability.decision.sign",
        str(decision_id),
        {
            "decision_id": decision_id,
            "signature_id": item.id,
            "key_id": key_id,
            "key_fingerprint": key.fingerprint,
            "envelope_version": ENVELOPE_VERSION,
            "envelope_sha256": envelope_digest,
        },
    )
    return _signature_dict(item, key), True


def _signature_dict(item: SignedDecision, key: SigningKey) -> dict:
    return {
        "id": item.id,
        "decision_id": item.decision_id,
        "principal_id": item.principal_id,
        "key_id": item.signing_key_id,
        "key_fingerprint": key.fingerprint,
        "algorithm": key.algorithm,
        "envelope_version": item.envelope_version,
        "envelope_sha256": item.envelope_sha256,
        "signature": item.signature_b64,
        "public_key_pem": key.public_key_pem,
        "verified_at": item.verified_at,
    }


def get_decision_signature(db: Session, decision_id: int) -> dict | None:
    item = db.scalar(select(SignedDecision).where(SignedDecision.decision_id == decision_id))
    if item is None:
        return None
    key = db.get(SigningKey, item.signing_key_id)
    decision = db.get(VulnerabilityDecision, decision_id)
    if key is None or decision is None:
        return {
            "id": item.id,
            "decision_id": item.decision_id,
            "key_id": item.signing_key_id,
            "envelope_version": item.envelope_version,
            "envelope_sha256": item.envelope_sha256,
            "signature": item.signature_b64,
            "verified_at": item.verified_at,
            "signature_valid": False,
            "trust_valid": False,
            "current_key_status": "missing",
        }

    current_envelope = signing_envelope(decision)
    current_digest = hashlib.sha256(current_envelope).hexdigest()
    signature_valid = current_digest == item.envelope_sha256
    if signature_valid:
        try:
            signature = _decode_signature(item.signature_b64)
            public_key = _registered_public_key(key)
            public_key.verify(signature, current_envelope)
        except (ValueError, InvalidSignature, TypeError):
            signature_valid = False

    key_status = "revoked" if key.revoked_at else "active"
    if key.expires_at is not None:
        expiry = key.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= utcnow():
            key_status = "expired"

    return {
        **_signature_dict(item, key),
        "signature_valid": signature_valid,
        "trust_valid": signature_valid and key_status == "active",
        "current_key_status": key_status,
    }
