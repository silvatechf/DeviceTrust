import base64
import hashlib
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import decision_approvals, decision_signatures, identity
from app.db import AuditChainState, AuditEntry, DecisionApproval, SessionLocal, SigningKey, utcnow

from .test_vulnerability_decisions import _finding


def _operator(name, scopes=None):
    with SessionLocal() as db:
        principal, _credential, token = identity.create_principal(
            db,
            name=name,
            kind="operator",
            scopes=set(
                scopes
                or {
                    "assessment:review",
                    "assessment:read",
                    "assessment:sign",
                    "assessment:approve",
                }
            ),
        )
        principal_id = principal.id
        db.commit()
    return principal_id, token


def _decision(client, monkeypatch, principal_id, token):
    finding_id = _finding()
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")
    response = client.post(
        f"/sbom/assessment-findings/{finding_id}/decisions",
        headers={"X-API-Key": token, "Idempotency-Key": f"approval-review-{finding_id}-1"},
        json={
            "state": "in_triage",
            "detail": "The vendor impact statement requires independent review.",
        },
    )
    assert response.status_code == 201, response.text
    return finding_id, response.json()["id"]


def _keypair():
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


def _register(principal_id, public_pem, purpose):
    with SessionLocal() as db:
        key = decision_signatures.register_public_key(
            db,
            principal_id=principal_id,
            public_key_pem=public_pem,
            purpose=purpose,
        )
        key_id = key.id
        db.commit()
    return key_id


def _sign_author(client, token, decision_id, principal_id):
    private_key, public_pem = _keypair()
    key_id = _register(principal_id, public_pem, "decision-signing")
    payload = client.get(
        f"/sbom/decisions/{decision_id}/signing-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": token},
    )
    assert payload.status_code == 200, payload.text
    signing_bytes = base64.b64decode(
        payload.json()["signing_payload_base64"], validate=True
    )
    signature = base64.b64encode(private_key.sign(signing_bytes)).decode("ascii")
    signed = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": key_id, "signature": signature},
    )
    assert signed.status_code == 201, signed.text
    return key_id


def _approval_submission(client, decision_id, approver_id, token):
    private_key, public_pem = _keypair()
    key_id = _register(approver_id, public_pem, "decision-approval")
    payload = client.get(
        f"/sbom/decisions/{decision_id}/approval-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": token},
    )
    assert payload.status_code == 200, payload.text
    data = payload.json()
    signing_bytes = base64.b64decode(data["signing_payload_base64"], validate=True)
    signature = base64.b64encode(private_key.sign(signing_bytes)).decode("ascii")
    return {
        "key_id": key_id,
        "approved_at": data["approved_at"],
        "signature": signature,
    }


def test_independent_approval_requires_author_signature_and_separate_operator_key(
    client, monkeypatch
):
    author_id, author_token = _operator("Decision author")
    approver_id, approver_token = _operator("Independent approver")
    _finding_id, decision_id = _decision(client, monkeypatch, author_id, author_token)

    _sign_author(client, author_token, decision_id, author_id)
    submission = _approval_submission(
        client, decision_id, approver_id, approver_token
    )

    response = client.post(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": approver_token},
        json=submission,
    )
    assert response.status_code == 201, response.text
    assert response.json()["approver_principal_id"] == approver_id
    assert response.json()["policy_version"] == decision_approvals.POLICY_VERSION
    approval_envelope = base64.b64decode(
        response.json()["approval_payload_base64"], validate=True
    )
    assert hashlib.sha256(approval_envelope).hexdigest() == response.json()["envelope_sha256"]
    verifier = serialization.load_pem_public_key(response.json()["public_key_pem"].encode("ascii"))
    verifier.verify(
        base64.b64decode(response.json()["signature"], validate=True),
        approval_envelope,
    )

    retry = client.post(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": approver_token},
        json=submission,
    )
    assert retry.status_code == 200
    assert retry.json()["id"] == response.json()["id"]

    status = client.get(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": author_token},
    )
    assert status.status_code == 200
    result = status.json()
    assert result["current_revision"] is True
    assert result["author_signature_trusted"] is True
    assert result["valid_approver_count"] == 1
    assert result["approval_policy_satisfied"] is True
    assert result["approvals"][0]["signature_valid"] is True
    assert result["approvals"][0]["trust_valid"] is True
    assert result["approvals"][0]["eligible_for_current_revision"] is True

    with SessionLocal() as db:
        rows = db.query(DecisionApproval).filter_by(decision_id=decision_id).all()
        assert len(rows) == 1


def test_author_cannot_approve_own_decision_with_a_second_key(client, monkeypatch):
    author_id, author_token = _operator("Self approval attempt")
    _finding_id, decision_id = _decision(client, monkeypatch, author_id, author_token)
    _sign_author(client, author_token, decision_id, author_id)
    _private_key, public_pem = _keypair()
    key_id = _register(author_id, public_pem, "decision-approval")

    response = client.get(
        f"/sbom/decisions/{decision_id}/approval-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": author_token},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "The decision author cannot approve their own decision"


def test_approval_is_blocked_until_author_signature_is_trusted(client, monkeypatch):
    author_id, author_token = _operator("Unsigned decision author")
    approver_id, approver_token = _operator("Approval blocked operator")
    _finding_id, decision_id = _decision(client, monkeypatch, author_id, author_token)
    _private_key, public_pem = _keypair()
    key_id = _register(approver_id, public_pem, "decision-approval")

    response = client.get(
        f"/sbom/decisions/{decision_id}/approval-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": approver_token},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == (
        "A currently trusted author signature is required before approval"
    )


def test_approval_rejects_a_decision_signing_key_as_approver_key(client, monkeypatch):
    author_id, author_token = _operator("Purpose test author")
    approver_id, approver_token = _operator("Purpose test approver")
    _finding_id, decision_id = _decision(client, monkeypatch, author_id, author_token)
    _sign_author(client, author_token, decision_id, author_id)
    _private_key, public_pem = _keypair()
    key_id = _register(approver_id, public_pem, "decision-signing")

    response = client.get(
        f"/sbom/decisions/{decision_id}/approval-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": approver_token},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Approval key is not bound to this operator and approval purpose"
    )


def test_new_decision_revision_invalidates_previous_approval_for_current_policy(
    client, monkeypatch
):
    author_id, author_token = _operator("Revision author")
    approver_id, approver_token = _operator("Revision approver")
    finding_id, decision_id = _decision(client, monkeypatch, author_id, author_token)
    _sign_author(client, author_token, decision_id, author_id)
    submission = _approval_submission(
        client, decision_id, approver_id, approver_token
    )
    approved = client.post(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": approver_token},
        json=submission,
    )
    assert approved.status_code == 201, approved.text

    revised = client.post(
        f"/sbom/assessment-findings/{finding_id}/decisions",
        headers={
            "X-API-Key": author_token,
            "Idempotency-Key": f"approval-review-{finding_id}-2",
        },
        json={
            "state": "in_triage",
            "detail": "The vendor supplied a new statement requiring reassessment.",
        },
    )
    assert revised.status_code == 201, revised.text
    assert revised.json()["revision"] == 2

    status = client.get(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": author_token},
    )
    assert status.status_code == 200
    result = status.json()
    assert result["current_revision"] is False
    assert result["approval_policy_satisfied"] is False
    assert result["approvals"][0]["signature_valid"] is True
    assert result["approvals"][0]["eligible_for_current_revision"] is False


def test_disabled_approver_signature_remains_verifiable_but_not_trusted(
    client, monkeypatch
):
    author_id, author_token = _operator("Approval history author")
    approver_id, approver_token = _operator("Approver later disabled")
    _finding_id, decision_id = _decision(client, monkeypatch, author_id, author_token)
    _sign_author(client, author_token, decision_id, author_id)
    submission = _approval_submission(
        client, decision_id, approver_id, approver_token
    )
    approved = client.post(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": approver_token},
        json=submission,
    )
    assert approved.status_code == 201, approved.text

    with SessionLocal() as db:
        identity.disable_principal(db, approver_id)
        db.commit()

    status = client.get(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": author_token},
    )
    result = status.json()
    assert result["approvals"][0]["signature_valid"] is True
    assert result["approvals"][0]["trust_valid"] is False
    assert result["approval_policy_satisfied"] is False


def test_approval_requires_assessment_approve_scope(client, monkeypatch):
    author_id, author_token = _operator("Scoped author")
    approver_id, approver_token = _operator(
        "Read-only approver",
        scopes={"assessment:read"},
    )
    _finding_id, decision_id = _decision(client, monkeypatch, author_id, author_token)
    _sign_author(client, author_token, decision_id, author_id)
    _private_key, public_pem = _keypair()
    key_id = _register(approver_id, public_pem, "decision-approval")

    response = client.get(
        f"/sbom/decisions/{decision_id}/approval-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": approver_token},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient API credential scope"


def test_expired_approval_payload_is_rejected(client, monkeypatch):
    author_id, author_token = _operator("Expired approval author")
    approver_id, approver_token = _operator("Expired approval reviewer")
    _finding_id, decision_id = _decision(client, monkeypatch, author_id, author_token)
    _sign_author(client, author_token, decision_id, author_id)
    _private_key, public_pem = _keypair()
    key_id = _register(approver_id, public_pem, "decision-approval")
    expired_at = (utcnow() - timedelta(minutes=31)).isoformat()
    response = client.post(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": approver_token},
        json={
            "key_id": key_id,
            "approved_at": expired_at,
            "signature": base64.b64encode(b"x" * 64).decode("ascii"),
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"] == (
        "approval payload has expired; request a new approval payload"
    )


def test_revoked_author_key_makes_approval_ineligible(client, monkeypatch):
    author_id, author_token = _operator("Revoked author key")
    approver_id, approver_token = _operator("Revocation policy approver")
    _finding_id, decision_id = _decision(client, monkeypatch, author_id, author_token)
    author_key_id = _sign_author(client, author_token, decision_id, author_id)
    submission = _approval_submission(
        client, decision_id, approver_id, approver_token
    )
    approved = client.post(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": approver_token},
        json=submission,
    )
    assert approved.status_code == 201, approved.text

    with SessionLocal() as db:
        decision_signatures.revoke_public_key(db, author_key_id)
        db.commit()

    status = client.get(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": author_token},
    )
    result = status.json()
    assert result["author_signature_trusted"] is False
    assert result["approvals"][0]["signature_valid"] is True
    assert result["approvals"][0]["trust_valid"] is True
    assert result["approvals"][0]["eligible_for_current_revision"] is False
    assert result["approval_policy_satisfied"] is False


def test_corrupted_approval_key_registry_fails_closed(client, monkeypatch):
    author_id, author_token = _operator("Corrupt approval registry author")
    approver_id, approver_token = _operator("Corrupt approval registry reviewer")
    _finding_id, decision_id = _decision(client, monkeypatch, author_id, author_token)
    _sign_author(client, author_token, decision_id, author_id)
    _private_key, public_pem = _keypair()
    key_id = _register(approver_id, public_pem, "decision-approval")

    with SessionLocal() as db:
        key = db.get(SigningKey, key_id)
        key.public_key_pem = "not a PEM public key"
        db.commit()

    response = client.get(
        f"/sbom/decisions/{decision_id}/approval-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": approver_token},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == (
        "Registered approval key integrity validation failed"
    )


def test_approval_and_audit_event_roll_back_together(client, monkeypatch):
    author_id, author_token = _operator("Approval transaction author")
    approver_id, approver_token = _operator("Approval transaction reviewer")
    _finding_id, decision_id = _decision(client, monkeypatch, author_id, author_token)
    _sign_author(client, author_token, decision_id, author_id)
    submission = _approval_submission(
        client, decision_id, approver_id, approver_token
    )
    with SessionLocal() as db:
        approval_count_before = db.query(DecisionApproval).count()
        audit_count_before = db.query(AuditEntry).count()
        chain_version_before = db.get(AuditChainState, 1).version

    original_record = decision_approvals.audit.record

    def fail_after_audit_append(db, actor, action, entity, payload):
        original_record(db, actor, action, entity, payload)
        raise RuntimeError("injected approval audit failure")

    monkeypatch.setattr(decision_approvals.audit, "record", fail_after_audit_append)
    with pytest.raises(RuntimeError, match="injected approval audit failure"):
        client.post(
            f"/sbom/decisions/{decision_id}/approval",
            headers={"X-API-Key": approver_token},
            json=submission,
        )
    monkeypatch.setattr(decision_approvals.audit, "record", original_record)

    with SessionLocal() as db:
        assert db.query(DecisionApproval).count() == approval_count_before
        assert db.query(AuditEntry).count() == audit_count_before
        assert db.get(AuditChainState, 1).version == chain_version_before
