import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from app import decision_signatures, identity
from app.db import SessionLocal, SignedDecision, VulnerabilityDecision

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

    with SessionLocal() as db:
        decision = db.get(VulnerabilityDecision, decision_id)
        signature = base64.b64encode(
            private_key.sign(decision_signatures.signing_envelope(decision))
        ).decode("ascii")

    response = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": key_id, "signature": signature},
    )
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["decision_id"] == decision_id
    assert result["key_fingerprint"] == fingerprint
    assert result["algorithm"] == "Ed25519"
    assert result["envelope_version"] == decision_signatures.ENVELOPE_VERSION

    verified = client.get(f"/sbom/decisions/{decision_id}/signature", headers={"X-API-Key": token})
    assert verified.status_code == 200
    assert verified.json()["signature_valid"] is True
    assert verified.json()["trust_valid"] is True
    assert verified.json()["current_key_status"] == "active"

    with SessionLocal() as db:
        rows = db.scalars(select(SignedDecision).where(SignedDecision.decision_id == decision_id)).all()
        assert len(rows) == 1
        assert rows[0].signature_b64 == signature


def test_tampered_decision_fails_signature_reverification(client, monkeypatch):
    principal_id, token = _operator()
    decision_id = _decision(client, monkeypatch, principal_id, token)
    private_key, public_pem = _keypair()
    key_id, _ = _register(principal_id, public_pem)

    with SessionLocal() as db:
        decision = db.get(VulnerabilityDecision, decision_id)
        signature = base64.b64encode(
            private_key.sign(decision_signatures.signing_envelope(decision))
        ).decode("ascii")

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


def test_revoked_key_remains_verifiable_but_is_not_trusted_for_new_signatures(client, monkeypatch):
    principal_id, token = _operator()
    decision_id = _decision(client, monkeypatch, principal_id, token)
    private_key, public_pem = _keypair()
    key_id, _ = _register(principal_id, public_pem)

    with SessionLocal() as db:
        decision = db.get(VulnerabilityDecision, decision_id)
        signature = base64.b64encode(
            private_key.sign(decision_signatures.signing_envelope(decision))
        ).decode("ascii")

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
    assert verified.json()["current_key_status"] == "revoked"


def test_signature_rejects_wrong_key_payload_and_cross_principal_key(client, monkeypatch):
    principal_id, token = _operator()
    decision_id = _decision(client, monkeypatch, principal_id, token)
    other_principal_id, _ = _operator()
    private_key, public_pem = _keypair()
    key_id, _ = _register(other_principal_id, public_pem)

    with SessionLocal() as db:
        decision = db.get(VulnerabilityDecision, decision_id)
        signature = base64.b64encode(
            private_key.sign(decision_signatures.signing_envelope(decision))
        ).decode("ascii")

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
    private_key, public_pem = _keypair()
    key_id, _ = _register(principal_id, public_pem)
    with SessionLocal() as db:
        decision = db.get(VulnerabilityDecision, decision_id)
        signature = base64.b64encode(
            private_key.sign(decision_signatures.signing_envelope(decision))
        ).decode("ascii")

    response = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": key_id, "signature": signature},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient API credential scope"


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
