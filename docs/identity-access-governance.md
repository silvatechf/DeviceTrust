# Identity and Access Governance

## Status

Proposed architecture and implementation plan. This document does not describe an implemented capability. The current API still uses one shared `DEVICETRUST_API_KEY` and records the literal actor `api-key`.

## Problem statement

A shared API key creates one trust domain: every holder can perform the same operations, a leaked key cannot be revoked for one client, and audit events cannot identify the operator or integration responsible for a decision. This is incompatible with defensible human review, credential-exposure evidence handling, and future VEX workflows.

The browser console currently sends the same `X-API-Key` header as API clients. Any migration must preserve a bounded transition path without silently retaining the shared key as a bypass.

## Goals

- Give each human operator or machine integration a stable, non-secret principal identity.
- Issue independently revocable API credentials with explicit expiry and least-privilege scopes.
- Store only a verifier for each high-entropy API token; show the raw token once at creation.
- Attribute every mutating audit event to the authenticated principal.
- Deny requests when a credential is unknown, expired, revoked, disabled, or missing the required scope.
- Keep the current modular-monolith and SQLAlchemy/Alembic architecture.
- Preserve a controlled migration path for the existing local console and API clients.

## Non-goals

- Human passwords, browser sessions, OAuth/OIDC federation, MFA, or an identity provider.
- Multi-tenant isolation or customer-facing SaaS.
- Device identity based on IP, MAC address, hostname, or inventory labels.
- A home-grown secrets vault, PKI, certificate authority, or automatic credential rotation.
- Automatic privilege escalation or a permanent shared-key fallback in managed mode.

## Domain model

### Principal

A principal represents an accountable actor, either an operator or a machine integration.

Proposed fields:

- `id`: immutable UUID.
- `name`: operator/integration display name, bounded and non-secret.
- `kind`: `operator` or `service`.
- `status`: `active` or `disabled`.
- `created_at`, `disabled_at`.

Principal identity is not authentication. A principal becomes an authenticated actor only through a valid credential.

### API credential

A credential belongs to exactly one principal.

Proposed fields:

- `id`: immutable UUID.
- `principal_id`: foreign key.
- `prefix`: non-secret lookup identifier; never sufficient to authenticate.
- `token_digest`: SHA-256 digest of a cryptographically random token with at least 256 bits of entropy.
- `scopes`: validated set of allow-listed scope strings.
- `created_at`, `expires_at`, `revoked_at`, `last_used_at`.

The token must be generated with a cryptographically secure random generator and returned only once. The database stores no raw token. SHA-256 is appropriate here only because the token is machine-generated with high entropy; it is not a password hashing strategy. Human-chosen passwords are out of scope.

Credential lookup uses the public prefix, then constant-time digest comparison. Prefixes are identifiers, not secrets. Authentication must fail closed for malformed or ambiguous credentials. Expiry and revocation are checked on every request; no positive authentication cache may extend credential validity.

## Authorization model

Use explicit scopes rather than introducing a role hierarchy before the product has multiple demonstrated role profiles. Initial scopes should map to actual route capabilities:

- `inventory:read` and `inventory:write`
- `evidence:read` and `evidence:write`
- `sbom:read` and `sbom:write`
- `assessment:read` and `assessment:write`
- `audit:read`
- `credentials:manage`

The implementation must maintain one route-to-scope matrix and test every protected route. Read access must not imply write access. Credential-management endpoints must require `credentials:manage`; token creation must never allow callers to grant scopes they do not possess. A principal's disabled status denies all its credentials.

Do not treat authentication as authorization. A valid token without the route's scope receives 403; missing or invalid authentication receives 401; unavailable managed-auth configuration receives 503.

## Audit attribution

Keep the audit actor field as a stable principal identifier (for example, `principal:<uuid>`), not a token, prefix, display name, or client-supplied value. The principal ID must come exclusively from the authenticated server-side context.

Never write raw credentials, authorization headers, token digests, or secret-bearing request data into audit payloads or application logs. Credential lifecycle events should record principal/credential identifiers and the operation, not token material.

The current hash-chain digest includes the actor string. Keeping the actor representation stable avoids rewriting historical audit entries. Legacy events with actor `api-key` remain historical records and must not be retroactively attributed to a newly created principal.

## Bootstrap and migration

The existing shared-key mode must not become an implicit fallback.

1. Add an explicit authentication mode setting with a backwards-compatible local default during the transition.
2. In `legacy` mode, the existing shared key continues to work only as the explicitly selected legacy mechanism. It must be represented as a clearly named legacy actor and documented as single-trust-domain behavior.
3. Add an offline administrative bootstrap command that creates the first principal and credential using direct local database access. Print the raw token once; do not expose bootstrap through an unauthenticated HTTP endpoint.
4. In `managed` mode, authenticate only against stored principal credentials. Ignore the legacy environment key completely; a managed-auth failure must never fall back to it.
5. Keep the `X-API-Key` transport header for compatibility with existing clients and the console. A managed token can replace the legacy key without changing the header contract.
6. Update the console connection copy to call the value an API token and ensure it remains only in page memory. Do not add localStorage, sessionStorage, cookies, or URL-based credential transport.
7. Document the operator migration, test both modes, and make managed mode the only supported mode before any shared or multi-user deployment.

The exact default and removal date for legacy mode must be decided against deployment and client usage evidence. Do not claim the shared key has been removed until the code and operational configuration prove it.

## Transaction and concurrency boundaries

- Credential creation, revocation, principal disablement, and their audit events must commit atomically.
- Credential validation must observe current revocation/expiry state on each request.
- Audit writer locking must remain acquired only after successful authentication and before a mutating transaction reads state.
- Failed authorization must not acquire the audit writer lock or create a domain/audit event.
- Avoid holding a database transaction open across network calls.
- Migration must preserve existing audit rows and their hashes.

## Required verification

### Authentication

- Missing, malformed, unknown, revoked, expired, and disabled-principal credentials are rejected.
- Managed mode ignores a valid legacy shared key and fails closed if managed configuration is unavailable.
- Legacy mode works only when explicitly selected.
- Prefix collisions or duplicate token digests cannot authenticate ambiguously.
- Authentication comparisons do not leak digest comparison results through ordinary control flow.

### Authorization

- Each route is tested for its required scope.
- A valid credential lacking a scope receives 403.
- Read-only credentials cannot mutate data.
- Credential-management actions cannot grant scopes beyond the caller's authority.
- Disabled principals invalidate all associated credentials immediately.

### Lifecycle and audit

- Raw tokens are returned once and never appear in database rows, API responses after creation, logs, or audit payloads.
- Revocation and expiry take effect on the next request.
- Credential creation/revocation and audit append are atomic on SQLite and PostgreSQL.
- Actor attribution uses the principal ID and cannot be spoofed by request input.
- Existing audit-chain hashes remain valid after migration and rollback tests.
- Credential last-use updates do not create unbounded write contention or break audit-chain serialization.

### Integration

- SQLite and PostgreSQL migration upgrade paths are tested.
- Existing local console and API clients are exercised in legacy and managed modes.
- The route-to-scope matrix covers every protected route, including product SBOM imports, reassessments, reports, and audit verification.

## Delivery sequence

1. **Foundation:** schema, token generation/verification, principal/credential services, explicit auth modes, route scope dependencies, offline bootstrap, and focused tests.
2. **Attribution:** update audit actor context and credential lifecycle audit events without changing historical hashes.
3. **Console migration:** preserve the header contract, update wording, and validate the browser-memory-only credential boundary.
4. **Operational hardening:** rate limits, retention, bootstrap custody, key rotation procedure, backup/restore, monitoring, and managed-mode deployment evidence.
5. **Future federation:** consider OIDC/SSO only when customer deployment requirements justify it.

## Residual limitations

Scoped API tokens do not provide human MFA, federated identity proof, tenant isolation, or protection from a compromised host/database administrator. A principal name is an administrative label, not proof of a person's legal identity. Audit hash chaining remains tamper-evident rather than immutable and still requires independent checkpoints for stronger assurance.
