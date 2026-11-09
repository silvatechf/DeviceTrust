import base64
import hashlib
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from app import decision_signatures, identity
from app.db import AuditChainState, AuditEntry, SessionLocal, SignedDecision, SigningKey, VulnerabilityDecision, utcnow

from .test_vulnerability_decisions import _finding


def _operator(scopes=None):
    with SessionLocal() as db:
        principal, _credential, token = identity.create_principal(
            db,
            name="Decision signing operator",
            kind="operator",
            scopes=set(scopes or {"assessment:review", "assessment:read", "assessment:sign"}),
        )
        principal_id = principal.id
        db.commit()
    return principal_id, token


def _decision(client, monkeypatch, principal_id, token):
    finding_id = _finding()
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")
    response = client.post(
        f"/sbom/assessment-findings/{finding_id}/decisions",
        headers={"X-API-Key": token, "Idempotency-Key": f"signing-review-{finding_id}"},
        json={
            "state": "in_triage",
            "detail": "The vendor impact statement is being reviewed before release.",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _keypair():
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


def _register(principal_id, public_pem):
    with SessionLocal() as db:
        key = decision_signatures.register_public_key(
            db, principal_id=principal_id, public_key_pem=public_pem
        )
        key_id = key.id
        fingerprint = key.fingerprint
        db.commit()
    return key_id, fingerprint


def _signature_for(client, token, decision_id, key_id, private_key):
    payload_response = client.get(
        f"/sbom/decisions/{decision_id}/signing-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": token},
    )
    assert payload_response.status_code == 200, payload_response.text
    payload = base64.b64decode(payload_response.json()["signing_payload_base64"], validate=True)
    return base64.b64encode(private_key.sign(payload)).decode("ascii")

def test_signing_envelope_is_domain_separated_and_deterministic(client, monkeypatch):
    principal_id, token = _operator()
    decision_id = _decision(client, monkeypatch, principal_id, token)
    with SessionLocal() as db:
        decision = db.get(VulnerabilityDecision, decision_id)
        first = decision_signatures.signing_envelope(decision)
        second = decision_signatures.signing_envelope(decision)
    assert first == second
    assert first.startswith(decision_signatures.DOMAIN_SEPARATOR)
    assert b'"envelope_version":"devicetrust.decision-signature.v1"' in first

def test_ed25519_signature_is_verified_and_persisted(client, monkeypatch):
    principal_id, token = _operator()
    decision_id = _decision(client, monkeypatch, principal_id, token)
    private_key, public_pem = _keypair()
    key_id, fingerprint = _register(principal_id, public_pem)

    signature = _signature_for(client, token, decision_id, key_id, private_key)

    response = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": key_id, "signature": signature},
    )
    assert response.status_code == 201, response.text
    result = response.json()
    retry = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": key_id, "signature": signature},
    )
    assert retry.status_code == 200
    assert retry.json()["id"] == result["id"]
    assert result["decision_id"] == decision_id
    assert result["key_fingerprint"] == fingerprint
    assert result["algorithm"] == "Ed25519"
    assert result["envelope_version"] == decision_signatures.ENVELOPE_VERSION

    verified = client.get(f"/sbom/decisions/{decision_id}/signature", headers={"X-API-Key": token})
    assert verified.status_code == 200
    assert verified.json()["signature_valid"] is True
    assert verified.json()["trust_valid"] is True
    assert verified.json()["signatures"][0]["signature"] == signature
    assert verified.json()["signatures"][0]["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    current_payload = base64.b64decode(verified.json()["signing_payload_base64"], validate=True)
    assert current_payload.startswith(decision_signatures.DOMAIN_SEPARATOR)
    assert hashlib.sha256(current_payload).hexdigest() == verified.json()["current_envelope_sha256"]
    assert verified.json()["signatures"][0]["current_key_status"] == "active"

    with SessionLocal() as db:
        rows = db.scalars(select(SignedDecision).where(SignedDecision.decision_id == decision_id)).all()
        assert len(rows) == 1
        assert rows[0].signature_b64 == signature


def test_tampered_decision_fails_signature_reverification(client, monkeypatch):
    principal_id, token = _operator()
    decision_id = _decision(client, monkeypatch, principal_id, token)
    private_key, public_pem = _keypair()
    key_id, _ = _register(principal_id, public_pem)

    signature = _signature_for(client, token, decision_id, key_id, private_key)

    signed = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": key_id, "signature": signature},
    )
    assert signed.status_code == 201

    with SessionLocal() as db:
        decision = db.get(VulnerabilityDecision, decision_id)
        decision.detail = "Privileged database modification changed the signed decision."
        db.commit()

    verified = client.get(f"/sbom/decisions/{decision_id}/signature", headers={"X-API-Key": token})
    assert verified.status_code == 200
    assert verified.json()["signature_valid"] is False
    assert verified.json()["trust_valid"] is False


def test_revoked_key_remains_verifiable_but_is_not_trusted_for_new_signatures(client, monkeypatch):
    principal_id, token = _operator()
    decision_id = _decision(client, monkeypatch, principal_id, token)
    private_key, public_pem = _keypair()
    key_id, _ = _register(principal_id, public_pem)

    signature = _signature_for(client, token, decision_id, key_id, private_key)

    signed = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": key_id, "signature": signature},
    )
    assert signed.status_code == 201

    with SessionLocal() as db:
        decision_signatures.revoke_public_key(db, key_id)
        db.commit()

    verified = client.get(f"/sbom/decisions/{decision_id}/signature", headers={"X-API-Key": token})
    assert verified.json()["signature_valid"] is True
    assert verified.json()["trust_valid"] is False
    assert verified.json()["signatures"][0]["current_key_status"] == "revoked"
    payload = client.get(
        f"/sbom/decisions/{decision_id}/signing-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": token},
    )
    assert payload.status_code == 403


def test_decision_can_be_resigned_after_key_rotation_without_losing_history(client, monkeypatch):
    principal_id, token = _operator()
    decision_id = _decision(client, monkeypatch, principal_id, token)
    first_private, first_public = _keypair()
    first_key_id, _ = _register(principal_id, first_public)
    first_signature = _signature_for(client, token, decision_id, first_key_id, first_private)
    first_response = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": first_key_id, "signature": first_signature},
    )
    assert first_response.status_code == 201
    with SessionLocal() as db:
        decision_signatures.revoke_public_key(db, first_key_id)
        db.commit()
    second_private, second_public = _keypair()
    second_key_id, _ = _register(principal_id, second_public)
    second_signature = _signature_for(client, token, decision_id, second_key_id, second_private)
    second_response = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": second_key_id, "signature": second_signature},
    )
    assert second_response.status_code == 201
    verified = client.get(f"/sbom/decisions/{decision_id}/signature", headers={"X-API-Key": token})
    result = verified.json()
    assert len(result["signatures"]) == 2
    assert result["signatures"][0]["current_key_status"] == "revoked"
    assert result["signatures"][0]["trust_valid"] is False
    assert result["signatures"][1]["current_key_status"] == "active"
    assert result["signatures"][1]["trust_valid"] is True
    assert result["trust_valid"] is True

def test_signature_rejects_wrong_key_payload_and_cross_principal_key(client, monkeypatch):
    principal_id, token = _operator()
    decision_id = _decision(client, monkeypatch, principal_id, token)
    other_principal_id, _ = _operator()
    _, public_pem = _keypair()
    key_id, _ = _register(other_principal_id, public_pem)

    payload = client.get(
        f"/sbom/decisions/{decision_id}/signing-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": token},
    )
    assert payload.status_code == 403

    signature = base64.b64encode(b"x" * 64).decode("ascii")
    response = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": key_id, "signature": signature},
    )
    assert response.status_code == 403

    private_key, public_pem = _keypair()
    own_key_id, _ = _register(principal_id, public_pem)
    invalid = base64.b64encode(b"x" * 64).decode("ascii")
    response = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": own_key_id, "signature": invalid},
    )
    assert response.status_code == 422


def test_signing_scope_is_separate_and_required(client, monkeypatch):
    principal_id, token = _operator(scopes={"assessment:review", "assessment:read"})
    decision_id = _decision(client, monkeypatch, principal_id, token)
    _, public_pem = _keypair()
    key_id, _ = _register(principal_id, public_pem)
    signature = base64.b64encode(b"x" * 64).decode("ascii")

    response = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": key_id, "signature": signature},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient API credential scope"


def test_signature_and_audit_event_roll_back_together(client, monkeypatch):
    principal_id, token = _operator()
    decision_id = _decision(client, monkeypatch, principal_id, token)
    private_key, public_pem = _keypair()
    key_id, _ = _register(principal_id, public_pem)
    signature = _signature_for(client, token, decision_id, key_id, private_key)
    with SessionLocal() as db:
        signed_before = db.query(SignedDecision).count()
        audit_before = db.query(AuditEntry).count()
        chain_version_before = db.get(AuditChainState, 1).version
    original_record = decision_signatures.audit.record
    def fail_after_audit_append(db, actor, action, entity, payload):
        original_record(db, actor, action, entity, payload)
        raise RuntimeError("injected signature audit failure")
    monkeypatch.setattr(decision_signatures.audit, "record", fail_after_audit_append)
    with pytest.raises(RuntimeError, match="injected signature audit failure"):
        client.post(
            f"/sbom/decisions/{decision_id}/signature",
            headers={"X-API-Key": token},
            json={"key_id": key_id, "signature": signature},
        )
    monkeypatch.setattr(decision_signatures.audit, "record", original_record)
    with SessionLocal() as db:
        assert db.query(SignedDecision).count() == signed_before
        assert db.query(AuditEntry).count() == audit_before
        assert db.get(AuditChainState, 1).version == chain_version_before

def test_service_principal_cannot_register_decision_signing_key():
    with SessionLocal() as db:
        principal, _credential, _token = identity.create_principal(
            db,
            name="Signing service principal",
            kind="service",
            scopes={"assessment:sign"},
        )
        principal_id = principal.id
        db.commit()
    _, public_pem = _keypair()
    with SessionLocal() as db:
        with pytest.raises(PermissionError, match="Only operator principals"):
            decision_signatures.register_public_key(
                db, principal_id=principal_id, public_key_pem=public_pem
            )
        db.rollback()

def test_expired_signing_key_cannot_provide_payload_or_sign(client, monkeypatch):
    principal_id, token = _operator()
    decision_id = _decision(client, monkeypatch, principal_id, token)
    _, public_pem = _keypair()
    key_id, _ = _register(principal_id, public_pem)
    with SessionLocal() as db:
        key = db.get(SigningKey, key_id)
        key.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    payload = client.get(
        f"/sbom/decisions/{decision_id}/signing-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": token},
    )
    assert payload.status_code == 403
    assert payload.json()["detail"] == "Signing key has expired"

def test_only_ed25519_public_keys_can_be_registered():
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

    principal_id, _ = _operator()
    rsa_key = generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with SessionLocal() as db:
        with pytest.raises(ValueError, match="only Ed25519"):
            decision_signatures.register_public_key(db, principal_id=principal_id, public_key_pem=pem)
        db.rollback()
