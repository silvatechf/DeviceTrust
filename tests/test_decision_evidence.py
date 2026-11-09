import base64
import hashlib

import rfc8785
from sqlalchemy import update

from app import decision_signatures, identity
from app.db import EvidenceArtifact, SessionLocal
from .conftest import H
from .test_decision_signatures import _keypair, _register, _signature_for
from .test_vulnerability_decisions import _finding


def _operator_with_scopes():
    with SessionLocal() as db:
        principal, _credential, token = identity.create_principal(
            db,
            name="Decision evidence author",
            kind="operator",
            scopes={
                "assessment:review",
                "assessment:read",
                "assessment:sign",
                "evidence:read",
                "evidence:write",
            },
        )
        principal_id = principal.id
        db.commit()
    return principal_id, token


def _artifact(client):
    observation = client.post(
        "/evidence",
        headers=H,
        json={
            "source_type": "manual",
            "attribute": "firmware_note",
            "value": "Evidence artifact for exact decision revision binding",
        },
    )
    assert observation.status_code == 201, observation.text
    observation_id = observation.json()["id"]
    raw = b"decision evidence binding fixture"
    uploaded = client.post(
        f"/evidence/{observation_id}/artifacts",
        headers={**H, "Content-Type": "application/octet-stream"},
        content=raw,
    )
    assert uploaded.status_code == 201, uploaded.text
    return uploaded.json()["id"], hashlib.sha256(raw).hexdigest()


def _decision(client, monkeypatch, principal_id, token, artifact_id):
    finding_id = _finding()
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")
    response = client.post(
        f"/sbom/assessment-findings/{finding_id}/decisions",
        headers={
            "X-API-Key": token,
            "Idempotency-Key": f"evidence-manifest-{finding_id}",
        },
        json={
            "state": "not_affected",
            "justification": "code_not_present",
            "detail": "The affected component is not present in the assessed release.",
            "evidence_references": [artifact_id],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_manifest_binds_verified_artifact_to_exact_decision_and_signature(client, monkeypatch):
    principal_id, token = _operator_with_scopes()
    artifact_id, artifact_digest = _artifact(client)
    decision_id = _decision(client, monkeypatch, principal_id, token, artifact_id)

    response = client.post(
        f"/sbom/decisions/{decision_id}/evidence-manifest",
        headers={"X-API-Key": token},
        json={"artifact_ids": [artifact_id]},
    )
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["integrity_valid"] is True
    assert result["manifest"]["decision_id"] == decision_id
    assert result["manifest"]["decision_revision"] == 1
    assert result["manifest"]["artifacts"][0]["artifact_id"] == artifact_id
    assert result["manifest"]["artifacts"][0]["sha256"] == artifact_digest
    assert result["manifest_sha256"] == hashlib.sha256(
        rfc8785.dumps(result["manifest"])
    ).hexdigest()

    private_key, public_pem = _keypair()
    key_id, _fingerprint = _register(principal_id, public_pem)
    payload = client.get(
        f"/sbom/decisions/{decision_id}/signing-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": token},
    )
    assert payload.status_code == 200, payload.text
    envelope = base64.b64decode(payload.json()["signing_payload_base64"], validate=True)
    assert b'"evidence_manifest_sha256":"' + result["manifest_sha256"].encode() + b'"' in envelope
    signed = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={
            "key_id": key_id,
            "signature": base64.b64encode(private_key.sign(envelope)).decode(),
        },
    )
    assert signed.status_code == 201, signed.text
    verified = client.get(
        f"/sbom/decisions/{decision_id}/signature", headers={"X-API-Key": token}
    )
    assert verified.status_code == 200
    assert verified.json()["signature_valid"] is True
    assert verified.json()["trust_valid"] is True

    with SessionLocal() as db:
        approver, _credential, approver_token = identity.create_principal(
            db,
            name="Independent evidence approver",
            kind="operator",
            scopes={"assessment:approve", "assessment:read"},
        )
        approver_id = approver.id
        approval_key = decision_signatures.register_public_key(
            db,
            principal_id=approver_id,
            public_key_pem=_keypair()[1],
            purpose="decision-approval",
        )
        approval_key_id = approval_key.id
        db.commit()
    approval_private, _ = _keypair()
    # Register the public half corresponding to the private key used below.
    approval_private, approval_public = _keypair()
    with SessionLocal() as db:
        decision_signatures.revoke_public_key(db, approval_key_id)
        approval_key = decision_signatures.register_public_key(
            db,
            principal_id=approver_id,
            public_key_pem=approval_public,
            purpose="decision-approval",
        )
        approval_key_id = approval_key.id
        db.commit()
    approval_payload = client.get(
        f"/sbom/decisions/{decision_id}/approval-payload",
        params={"key_id": approval_key_id},
        headers={"X-API-Key": approver_token},
    )
    assert approval_payload.status_code == 200, approval_payload.text
    approval_bytes = base64.b64decode(
        approval_payload.json()["signing_payload_base64"], validate=True
    )
    assert result["manifest_sha256"].encode() in approval_bytes
    approved = client.post(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": approver_token},
        json={
            "key_id": approval_key_id,
            "approved_at": approval_payload.json()["approved_at"],
            "signature": base64.b64encode(
                approval_private.sign(approval_bytes)
            ).decode("ascii"),
        },
    )
    assert approved.status_code == 201, approved.text
    approval_status = client.get(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": token},
    )
    assert approval_status.status_code == 200
    assert approval_status.json()["approval_policy_satisfied"] is True


def test_manifest_requires_artifact_id_in_original_decision_references(client, monkeypatch):
    principal_id, token = _operator_with_scopes()
    artifact_id, _ = _artifact(client)
    decision_id = _decision(client, monkeypatch, principal_id, token, artifact_id + "x")
    response = client.post(
        f"/sbom/decisions/{decision_id}/evidence-manifest",
        headers={"X-API-Key": token},
        json={"artifact_ids": [artifact_id]},
    )
    assert response.status_code == 422
    assert "already referenced" in response.json()["detail"]


def test_manifest_is_immutable_and_idempotent(client, monkeypatch):
    principal_id, token = _operator_with_scopes()
    artifact_id, _ = _artifact(client)
    decision_id = _decision(client, monkeypatch, principal_id, token, artifact_id)

    first = client.post(
        f"/sbom/decisions/{decision_id}/evidence-manifest",
        headers={"X-API-Key": token},
        json={"artifact_ids": [artifact_id]},
    )
    assert first.status_code == 201, first.text
    retry = client.post(
        f"/sbom/decisions/{decision_id}/evidence-manifest",
        headers={"X-API-Key": token},
        json={"artifact_ids": [artifact_id]},
    )
    assert retry.status_code == 200
    assert retry.json()["manifest_sha256"] == first.json()["manifest_sha256"]


def test_manifest_cannot_be_added_after_decision_signature(client, monkeypatch):
    principal_id, token = _operator_with_scopes()
    artifact_id, _ = _artifact(client)
    decision_id = _decision(client, monkeypatch, principal_id, token, artifact_id)
    private_key, public_pem = _keypair()
    key_id, _ = _register(principal_id, public_pem)
    signature = _signature_for(client, token, decision_id, key_id, private_key)
    signed = client.post(
        f"/sbom/decisions/{decision_id}/signature",
        headers={"X-API-Key": token},
        json={"key_id": key_id, "signature": signature},
    )
    assert signed.status_code == 201
    blocked = client.post(
        f"/sbom/decisions/{decision_id}/evidence-manifest",
        headers={"X-API-Key": token},
        json={"artifact_ids": [artifact_id]},
    )
    assert blocked.status_code == 409


def test_manifest_artifact_tampering_invalidates_manifest_and_signing_payload(client, monkeypatch):
    principal_id, token = _operator_with_scopes()
    artifact_id, _ = _artifact(client)
    decision_id = _decision(client, monkeypatch, principal_id, token, artifact_id)
    created = client.post(
        f"/sbom/decisions/{decision_id}/evidence-manifest",
        headers={"X-API-Key": token},
        json={"artifact_ids": [artifact_id]},
    )
    assert created.status_code == 201
    private_key, public_pem = _keypair()
    key_id, _ = _register(principal_id, public_pem)

    with SessionLocal() as db:
        db.execute(
            update(EvidenceArtifact)
            .where(EvidenceArtifact.id == artifact_id)
            .values(content=b"tampered decision evidence")
        )
        db.commit()

    manifest = client.get(
        f"/sbom/decisions/{decision_id}/evidence-manifest",
        headers={"X-API-Key": token},
    )
    assert manifest.status_code == 200
    assert manifest.json()["integrity_valid"] is False
    payload = client.get(
        f"/sbom/decisions/{decision_id}/signing-payload",
        params={"key_id": key_id},
        headers={"X-API-Key": token},
    )
    assert payload.status_code == 503


def test_manifest_read_scope_is_separate_from_binding_scope(client, monkeypatch):
    principal_id, token = _operator_with_scopes()
    artifact_id, _ = _artifact(client)
    decision_id = _decision(client, monkeypatch, principal_id, token, artifact_id)
    created = client.post(
        f"/sbom/decisions/{decision_id}/evidence-manifest",
        headers={"X-API-Key": token},
        json={"artifact_ids": [artifact_id]},
    )
    assert created.status_code == 201, created.text
    with SessionLocal() as db:
        _reader, _credential, read_token = identity.create_principal(
            db,
            name="Evidence manifest reader",
            kind="service",
            scopes={"assessment:read"},
        )
        db.commit()
    response = client.get(
        f"/sbom/decisions/{decision_id}/evidence-manifest",
        headers={"X-API-Key": read_token},
    )
    assert response.status_code == 200
    denied = client.post(
        f"/sbom/decisions/{decision_id}/evidence-manifest",
        headers={"X-API-Key": read_token},
        json={"artifact_ids": [artifact_id]},
    )
    assert denied.status_code == 403
