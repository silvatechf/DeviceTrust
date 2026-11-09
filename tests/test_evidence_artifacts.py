import hashlib

import pytest
from sqlalchemy import update

from app import evidence_artifacts, identity
from app.db import AuditEntry, EvidenceArtifact, SessionLocal
from app.main import MAX_EVIDENCE_ARTIFACT_BYTES

from .conftest import H


def _observation(client):
    response = client.post(
        "/evidence",
        json={
            "source_type": "manual",
            "attribute": "firmware_note",
            "value": "Firmware evidence supplied for integrity testing",
        },
        headers=H,
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_artifact_upload_is_server_hashed_idempotent_and_downloadable(client):
    observation_id = _observation(client)
    payload = b"%PDF-1.7\nsynthetic evidence artifact\n"
    expected_digest = hashlib.sha256(payload).hexdigest()

    created = client.post(
        f"/evidence/{observation_id}/artifacts",
        content=payload,
        headers={**H, "Content-Type": "application/pdf"},
    )
    assert created.status_code == 201, created.text
    result = created.json()
    assert result["created"] is True
    assert result["sha256"] == expected_digest
    assert result["byte_size"] == len(payload)
    assert result["media_type"] == "application/pdf"
    assert result["verification"]["valid"] is True
    with SessionLocal() as db:
        event = db.query(AuditEntry).filter_by(action="evidence.artifact.attach").order_by(AuditEntry.id.desc()).first()
        assert event is not None
        assert event.payload["sha256"] == expected_digest
        assert event.payload["artifact_id"] == result["id"]
        assert payload.decode() not in str(event.payload)

    retried = client.post(
        f"/evidence/{observation_id}/artifacts",
        content=payload,
        headers={**H, "Content-Type": "application/pdf"},
    )
    assert retried.status_code == 200
    assert retried.json()["id"] == result["id"]
    assert retried.json()["created"] is False

    listed = client.get(f"/evidence/{observation_id}/artifacts", headers=H)
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [result["id"]]

    metadata = client.get(f"/evidence/artifacts/{result['id']}", headers=H)
    assert metadata.status_code == 200
    assert metadata.json()["integrity_valid"] is True

    verified = client.get(
        f"/evidence/artifacts/{result['id']}/verify", headers=H
    )
    assert verified.status_code == 200
    assert verified.json()["valid"] is True
    assert verified.json()["actual_sha256"] == expected_digest

    downloaded = client.get(
        f"/evidence/artifacts/{result['id']}/content", headers=H
    )
    assert downloaded.status_code == 200
    assert downloaded.content == payload
    assert downloaded.headers["content-type"] == "application/octet-stream"
    assert downloaded.headers["x-content-type-options"] == "nosniff"
    assert downloaded.headers["content-disposition"].startswith("attachment;")


def test_artifact_integrity_failure_is_detected_and_download_fails_closed(client):
    observation_id = _observation(client)
    payload = b"immutable evidence bytes"
    created = client.post(
        f"/evidence/{observation_id}/artifacts",
        content=payload,
        headers={**H, "Content-Type": "application/octet-stream"},
    )
    assert created.status_code == 201, created.text
    artifact_id = created.json()["id"]

    with SessionLocal() as db:
        db.execute(
            update(EvidenceArtifact)
            .where(EvidenceArtifact.id == artifact_id)
            .values(content=b"tampered evidence bytes")
        )
        db.commit()

    verified = client.get(
        f"/evidence/artifacts/{artifact_id}/verify", headers=H
    )
    assert verified.status_code == 200
    assert verified.json()["valid"] is False
    assert verified.json()["digest_valid"] is False

    downloaded = client.get(
        f"/evidence/artifacts/{artifact_id}/content", headers=H
    )
    assert downloaded.status_code == 503
    assert downloaded.json()["detail"] == (
        "Stored evidence artifact failed integrity verification"
    )


def test_artifact_upload_enforces_size_type_and_observation_boundaries(client):
    observation_id = _observation(client)
    oversized = client.post(
        f"/evidence/{observation_id}/artifacts",
        content=b"x" * (MAX_EVIDENCE_ARTIFACT_BYTES + 1),
        headers={**H, "Content-Type": "application/octet-stream"},
    )
    assert oversized.status_code == 413

    unsupported = client.post(
        f"/evidence/{observation_id}/artifacts",
        content=b"evidence",
        headers={**H, "Content-Type": "image/svg+xml"},
    )
    assert unsupported.status_code == 415

    empty = client.post(
        f"/evidence/{observation_id}/artifacts",
        content=b"",
        headers={**H, "Content-Type": "application/octet-stream"},
    )
    assert empty.status_code == 422

    missing = client.post(
        "/evidence/999999/artifacts",
        content=b"evidence",
        headers={**H, "Content-Type": "application/octet-stream"},
    )
    assert missing.status_code == 404


def test_artifact_routes_require_evidence_scopes(client):
    from app import identity

    assert identity.required_scopes(
        "POST", "/evidence/123/artifacts"
    ) == frozenset({"evidence:write"})
    assert identity.required_scopes(
        "GET", "/evidence/123/artifacts"
    ) == frozenset({"evidence:read"})
    assert identity.required_scopes(
        "GET", "/evidence/artifacts/12345678-1234-1234-1234-123456789abc"
    ) == frozenset({"evidence:read"})
    assert identity.required_scopes(
        "GET", "/evidence/artifacts/12345678-1234-1234-1234-123456789abc/verify"
    ) == frozenset({"evidence:read"})
    assert identity.required_scopes(
        "GET", "/evidence/artifacts/12345678-1234-1234-1234-123456789abc/content"
    ) == frozenset({"evidence:read"})


def test_managed_read_scope_cannot_upload_artifacts(client, monkeypatch):
    observation_id = _observation(client)
    payload = b"managed scope artifact"
    created = client.post(
        f"/evidence/{observation_id}/artifacts",
        content=payload,
        headers={**H, "Content-Type": "application/octet-stream"},
    )
    assert created.status_code == 201
    artifact_id = created.json()["id"]

    with SessionLocal() as db:
        _principal, _credential, read_token = identity.create_principal(
            db,
            name="Evidence read-only integration",
            kind="service",
            scopes={"evidence:read"},
        )
        _writer, _write_credential, write_token = identity.create_principal(
            db,
            name="Evidence write-only integration",
            kind="service",
            scopes={"evidence:write"},
        )
        db.commit()

    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")
    assert client.get(
        f"/evidence/artifacts/{artifact_id}", headers={"X-API-Key": read_token}
    ).status_code == 200
    denied = client.post(
        f"/evidence/{observation_id}/artifacts",
        content=b"unauthorized upload",
        headers={"X-API-Key": read_token, "Content-Type": "application/octet-stream"},
    )
    assert denied.status_code == 403
    assert client.get(
        f"/evidence/artifacts/{artifact_id}", headers={"X-API-Key": write_token}
    ).status_code == 403
    assert client.post(
        f"/evidence/{observation_id}/artifacts",
        content=b"authorized write",
        headers={"X-API-Key": write_token, "Content-Type": "application/octet-stream"},
    ).status_code == 201


def test_artifact_and_audit_event_roll_back_together(client, monkeypatch):
    observation_id = _observation(client)
    with SessionLocal() as db:
        artifact_count = db.query(EvidenceArtifact).count()
        audit_count = db.query(AuditEntry).count()

    original_record = evidence_artifacts.audit.record

    def fail_after_audit_append(db, actor, action, entity, payload):
        original_record(db, actor, action, entity, payload)
        raise RuntimeError("injected artifact audit failure")

    monkeypatch.setattr(evidence_artifacts.audit, "record", fail_after_audit_append)
    with pytest.raises(RuntimeError, match="injected artifact audit failure"):
        client.post(
            f"/evidence/{observation_id}/artifacts",
            content=b"rollback artifact",
            headers={**H, "Content-Type": "application/octet-stream"},
        )

    with SessionLocal() as db:
        assert db.query(EvidenceArtifact).count() == artifact_count
        assert db.query(AuditEntry).count() == audit_count


def test_artifact_byte_length_mismatch_is_detected(client):
    observation_id = _observation(client)
    payload = b"evidence byte length fixture"
    created = client.post(
        f"/evidence/{observation_id}/artifacts",
        content=payload,
        headers={**H, "Content-Type": "application/octet-stream"},
    )
    assert created.status_code == 201, created.text
    artifact_id = created.json()["id"]

    with SessionLocal() as db:
        db.execute(
            update(EvidenceArtifact)
            .where(EvidenceArtifact.id == artifact_id)
            .values(byte_size=len(payload) + 1)
        )
        db.commit()

    verified = client.get(
        f"/evidence/artifacts/{artifact_id}/verify", headers=H
    )
    assert verified.status_code == 200
    assert verified.json()["digest_valid"] is True
    assert verified.json()["size_valid"] is False
    assert verified.json()["valid"] is False
    assert client.get(
        f"/evidence/artifacts/{artifact_id}/content", headers=H
    ).status_code == 503
