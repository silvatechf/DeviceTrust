from datetime import timedelta
import re

import pytest
from sqlalchemy import select
from fastapi.routing import APIRoute

from app import identity
from app.db import APICredential, SessionLocal, utcnow
from app.main import app, auth
from .conftest import H


def _issue(scopes):
    with SessionLocal() as db:
        _principal, credential, token = identity.create_principal(
            db,
            name="Identity test principal",
            kind="service",
            scopes=set(scopes),
        )
        principal_id = principal.id
        credential_id = credential.id
        db.commit()
    return principal_id, credential_id, token


def test_managed_token_authentication_and_scope_enforcement(client, monkeypatch):
    _, _, token = _issue({"inventory:read"})
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")
    monkeypatch.setenv("DEVICETRUST_API_KEY", "legacy-test-key")

    assert client.get("/devices", headers={"X-API-Key": token}).status_code == 200
    denied = client.post(
        "/products",
        json={"manufacturer": "Test", "product_name": "Must be denied"},
        headers={"X-API-Key": token},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "Insufficient API credential scope"


def test_managed_mode_never_falls_back_to_legacy_shared_key(client, monkeypatch):
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")
    monkeypatch.setenv("DEVICETRUST_API_KEY", "test-key")

    response = client.get("/devices", headers=H)
    assert response.status_code == 401


def test_revoked_credential_is_rejected_on_next_request(client, monkeypatch):
    _, credential_id, token = _issue({"inventory:read"})
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")
    assert client.get("/devices", headers={"X-API-Key": token}).status_code == 200

    with SessionLocal() as db:
        identity.revoke_credential(db, credential_id)
        db.commit()

    assert client.get("/devices", headers={"X-API-Key": token}).status_code == 401


def test_disabled_principal_invalidates_all_credentials(client, monkeypatch):
    principal_id, _, token = _issue({"inventory:read"})
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")

    with SessionLocal() as db:
        identity.disable_principal(db, principal_id)
        db.commit()

    assert client.get("/devices", headers={"X-API-Key": token}).status_code == 401


def test_expired_credential_is_rejected(client, monkeypatch):
    with SessionLocal() as db:
        principal, credential, token = identity.create_principal(
            db,
            name="Expired principal",
            kind="operator",
            scopes={"inventory:read"},
            expires_at=utcnow() + timedelta(days=1),
        )
        credential.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()

    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")
    assert client.get("/devices", headers={"X-API-Key": token}).status_code == 401


def test_raw_token_is_not_persisted_and_scopes_are_allow_listed():
    with SessionLocal() as db:
        principal, credential, token = identity.create_principal(
            db,
            name="Secret handling test",
            kind="service",
            scopes={"sbom:read"},
        )
        stored = db.scalar(select(APICredential).where(APICredential.id == credential.id))
        assert stored is not None
        assert token not in stored.token_digest
        assert stored.token_digest != token
        assert stored.prefix in token
        assert stored.scopes == ["sbom:read"]
        db.rollback()

    with SessionLocal() as db:
        with pytest.raises(ValueError, match="allow-listed"):
            identity.create_principal(
                db,
                name="Invalid scope",
                kind="service",
                scopes={"admin:*"},
            )
        db.rollback()


def test_scope_matrix_is_explicit_and_least_privilege():
    assert identity.required_scopes("GET", "/devices") == frozenset({"inventory:read"})
    assert identity.required_scopes("POST", "/devices") == frozenset({"inventory:write"})
    assert identity.required_scopes("GET", "/audit") == frozenset({"audit:read"})
    assert identity.required_scopes("GET", "/devices/EDGE-1/report") == frozenset(
        {"inventory:read", "assessment:read", "audit:read"}
    )
    assert identity.required_scopes("DELETE", "/devices/EDGE-1") is None


def test_every_authenticated_route_has_an_explicit_scope_policy():
    def includes_auth(dependant):
        if dependant.call is auth:
            return True
        return any(includes_auth(child) for child in dependant.dependencies)

    protected_routes = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or not includes_auth(route.dependant):
            continue
        path = re.sub(r"\{[^}]+\}", "placeholder", route.path)
        for method in route.methods or set():
            if method in {"HEAD", "OPTIONS"}:
                continue
            protected_routes.append((method, path))
            assert identity.required_scopes(method, path) is not None, (
                f"Missing scope policy for {method} {route.path}"
            )

    assert protected_routes
