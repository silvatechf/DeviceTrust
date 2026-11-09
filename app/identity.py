import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import APICredential, Principal, utcnow

ALLOWED_SCOPES = frozenset(
    {
        "inventory:read",
        "inventory:write",
        "evidence:read",
        "evidence:write",
        "sbom:read",
        "sbom:write",
        "assessment:read",
        "assessment:write",
        "audit:read",
        "credentials:manage",
    }
)
_TOKEN_PATTERN = re.compile(r"\Adtk_([0-9a-f]{12})_([A-Za-z0-9_-]{43})\Z")

# Route authorization is intentionally explicit. A new protected route must be
# added here; unknown routes fail closed rather than inheriting broad access.
_ROUTE_SCOPES = (
    ("POST", re.compile(r"/products"), frozenset({"inventory:write"})),
    ("POST", re.compile(r"/products/[^/]+/releases"), frozenset({"inventory:write"})),
    ("POST", re.compile(r"/product-releases/[^/]+/sbom"), frozenset({"sbom:write"})),
    ("GET", re.compile(r"/product-releases/[^/]+/sbom"), frozenset({"sbom:read"})),
    ("GET", re.compile(r"/product-releases/[^/]+/sbom/diff"), frozenset({"sbom:read"})),
    ("POST", re.compile(r"/sbom/imports/[^/]+/assessments"), frozenset({"assessment:write"})),
    ("GET", re.compile(r"/sbom/imports/[^/]+/assessments"), frozenset({"assessment:read"})),
    ("GET", re.compile(r"/sbom/imports/[^/]+/assessments/[^/]+/findings"), frozenset({"assessment:read"})),
    ("GET", re.compile(r"/sbom/imports/[^/]+/components"), frozenset({"sbom:read"})),
    ("GET", re.compile(r"/sbom/components/[^/]+/findings"), frozenset({"sbom:read"})),
    ("POST", re.compile(r"/evidence"), frozenset({"evidence:write"})),
    ("GET", re.compile(r"/evidence"), frozenset({"evidence:read"})),
    ("GET", re.compile(r"/evidence/normalized"), frozenset({"evidence:read"})),
    ("POST", re.compile(r"/devices"), frozenset({"inventory:write"})),
    ("GET", re.compile(r"/devices"), frozenset({"inventory:read"})),
    ("GET", re.compile(r"/devices/[^/]+"), frozenset({"inventory:read"})),
    ("PUT", re.compile(r"/devices/[^/]+/security"), frozenset({"inventory:write"})),
    ("GET", re.compile(r"/devices/[^/]+/posture"), frozenset({"inventory:read"})),
    ("POST", re.compile(r"/devices/[^/]+/sbom"), frozenset({"sbom:write"})),
    ("GET", re.compile(r"/devices/[^/]+/vulnerabilities"), frozenset({"assessment:read"})),
    ("PATCH", re.compile(r"/vulnerabilities/[^/]+"), frozenset({"assessment:write"})),
    (
        "GET",
        re.compile(r"/devices/[^/]+/report"),
        frozenset({"inventory:read", "assessment:read", "audit:read"}),
    ),
    ("GET", re.compile(r"/audit"), frozenset({"audit:read"})),
    ("GET", re.compile(r"/audit/verify"), frozenset({"audit:read"})),
)


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    principal_id: str
    scopes: frozenset[str]


def required_scopes(method: str, path: str) -> frozenset[str] | None:
    for route_method, pattern, scopes in _ROUTE_SCOPES:
        if method.upper() == route_method and pattern.fullmatch(path):
            return scopes
    return None


def create_principal(
    db: Session,
    *,
    name: str,
    kind: str,
    scopes: set[str] | frozenset[str],
    expires_at=None,
) -> tuple[Principal, APICredential, str]:
    normalized_name = name.strip()
    normalized_scopes = sorted(set(scopes))
    if not normalized_name or len(normalized_name) > 120:
        raise ValueError("Principal name must contain 1 to 120 characters")
    if kind not in {"operator", "service"}:
        raise ValueError("Principal kind must be operator or service")
    if not normalized_scopes or not set(normalized_scopes).issubset(ALLOWED_SCOPES):
        raise ValueError("At least one valid, allow-listed scope is required")
    now = utcnow()
    if expires_at is None:
        expires_at = now + timedelta(days=90)
    elif expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now or expires_at > now + timedelta(days=365):
        raise ValueError("Credential expiry must be within the next 365 days")

    principal = Principal(
        id=str(uuid4()),
        name=normalized_name,
        kind=kind,
        status="active",
        created_at=now,
    )
    prefix = secrets.token_hex(6)
    raw_token = f"dtk_{prefix}_{secrets.token_urlsafe(32)}"
    credential = APICredential(
        id=str(uuid4()),
        principal_id=principal.id,
        prefix=prefix,
        token_digest=hashlib.sha256(raw_token.encode("ascii")).hexdigest(),
        scopes=normalized_scopes,
        created_at=now,
        expires_at=expires_at,
    )
    db.add(principal)
    db.add(credential)
    db.flush()
    return principal, credential, raw_token


def authenticate(db: Session, raw_token: str) -> AuthenticatedPrincipal | None:
    if not raw_token or len(raw_token) > 100:
        return None
    match = _TOKEN_PATTERN.fullmatch(raw_token)
    if match is None:
        return None

    credential = db.scalar(
        select(APICredential).where(APICredential.prefix == match.group(1))
    )
    if credential is None:
        return None

    candidate_digest = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
    if not hmac.compare_digest(candidate_digest, credential.token_digest):
        return None

    principal = db.get(Principal, credential.principal_id)
    if principal is None or principal.status != "active" or credential.revoked_at is not None:
        return None
    now = utcnow()
    if credential.expires_at is not None:
        expires_at = credential.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            return None

    scopes = frozenset(credential.scopes or [])
    if not scopes.issubset(ALLOWED_SCOPES):
        return None
    return AuthenticatedPrincipal(principal_id=principal.id, scopes=scopes)


def revoke_credential(db: Session, credential_id: str) -> None:
    credential = db.get(APICredential, credential_id)
    if credential is None:
        raise LookupError("Credential not found")
    if credential.revoked_at is None:
        credential.revoked_at = utcnow()
        db.flush()


def disable_principal(db: Session, principal_id: str) -> None:
    principal = db.get(Principal, principal_id)
    if principal is None:
        raise LookupError("Principal not found")
    if principal.status != "disabled":
        principal.status = "disabled"
        principal.disabled_at = utcnow()
        db.flush()
