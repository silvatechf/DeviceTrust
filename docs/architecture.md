# Architecture

## 1. Design in one sentence

DeviceTrust is a Python modular monolith: FastAPI exposes the HTTP API, domain modules implement posture/SBOM/audit behavior, and SQLAlchemy persists the records.

It is deliberately a single application. The current scope does not justify the operational cost of microservices.

## 2. Request flow

```mermaid
flowchart TD
    CLIENT[API client / local console] --> API[FastAPI route]
    API --> AUTH[API-key dependency]
    AUTH --> VALIDATE[Pydantic or explicit JSON validation]
    VALIDATE --> SERVICE[Domain function / service]
    SERVICE --> ORM[SQLAlchemy session]
    ORM --> DB[(SQLite default / PostgreSQL configured)]
    SERVICE --> RESPONSE[HTTP response]
```

For normal typed endpoints, Pydantic validates request models. The SBOM route reads the request stream directly so it can enforce a 2 MiB body limit before parsing JSON.

## 3. Main modules

| Module | Responsibility |
|---|---|
| `app/main.py` | FastAPI app, routes, authentication dependency, request orchestration and response serialization |
| `app/schemas.py` | Pydantic request contracts and field constraints |
| `app/db.py` | SQLAlchemy models, engine/session setup and database access |
| `app/posture.py` | Rules that assess the declared device security profile |
| `app/sbom.py` | CycloneDX subset parsing, PURL validation, local demo matching and optional OSV lookup |
| `app/product_sbom.py` | Product/release SBOM persistence, component occurrences, idempotency and import comparison |
| `app/evidence_normalization.py` | Pure normalizers for selected evidence attributes |
| `app/audit.py` | SHA-256 audit hashing and chain verification |
| `web/` | Static same-origin operator console |

Routes coordinate work; domain rules should remain in their relevant modules rather than growing inside route handlers.

## 4. Data flows

### Device posture

The posture service evaluates declared fields such as authentication, encryption, update mechanism, secure boot and internet exposure. Missing fields produce `unverified` findings. The input is declared metadata, not a measurement collected from the device.

### Evidence observations

```mermaid
flowchart TD
    SOURCE[External or manual source] --> POST[POST /evidence]
    POST --> AUTH[Shared API key]
    AUTH --> VALID[Schema, allowlist and bounds]
    VALID --> DEVICE{Device ID supplied?}
    DEVICE -->|Known ID| CHECK[Check device exists]
    DEVICE -->|No ID| UNASSIGNED[Keep unassigned]
    CHECK --> STORE[Persist as unverified]
    UNASSIGNED --> STORE
    STORE --> AUDIT[Audit metadata and digest]
    STORE --> READ[GET /evidence]
    STORE --> NORMAL[GET /evidence/normalized]
```

The normalized endpoint is a read-only projection. It preserves the raw value and does not change verification status or posture.

### SBOM and vulnerability findings

The API caps the request body at 2 MiB. The parser accepts a bounded CycloneDX JSON subset, validates component names/versions and PURLs, then checks the local synthetic advisory set. If `DEVICETRUST_OSV=1`, it also makes best-effort OSV queries. A failed or empty lookup is not proof that a component is safe.

### Product SBOM comparison

The authenticated `GET /product-releases/{release_id}/sbom/diff` endpoint compares two accepted imports belonging to the same product release. It matches components by a version-independent Package URL identity, then reports additions, removals, version changes and source-name changes. Duplicate package identities are reported as ambiguous. Components without a usable PURL remain unidentified and are not matched by name or ordinal. The comparison is read-only and does not re-evaluate vulnerability findings.

### Triage and audit

A triage update requires a justification. State-changing operations append audit entries. Each entry hashes its content and the previous entry hash. The chain can reveal changes to retained entries, but it has no external checkpoint and is not immutable storage.

## 5. Trust boundaries

- API clients are untrusted; protected routes use one shared API key.
- The key represents a broad local operator boundary, not a human identity or role.
- Uploaded SBOM and evidence values are untrusted input.
- Evidence references are opaque; the application does not fetch them.
- Device security attributes are declarations and are not independently attested.
- OSV is an external dependency and is optional/best-effort.
- The database and audit chain share the same trust boundary; a privileged database attacker can rewrite both.

## 6. Persistence and deployment

SQLite is the default local database. PostgreSQL can be selected with `DATABASE_URL`. Alembic owns schema evolution: apply migrations explicitly with `alembic upgrade head`; application startup does not create or alter tables. The container startup script applies pending migrations before launching the API, and the demo seeder upgrades its target database before inserting synthetic records.

The initial migration establishes the existing schema; it does not automatically convert an arbitrary legacy SQLite database. Follow the backup, schema-verification and explicit `alembic stamp` procedure in the [Demo runbook](demo-runbook.md) only when the existing schema has been verified to match the baseline.

CI covers SQLite migration upgrade/downgrade, ORM metadata drift and PostgreSQL persistence after engine disposal/reconnection. A clean local Compose deployment, backup/restore and deployment rollback have not yet been demonstrated.

The static console is served from the same FastAPI origin. It avoids a separate frontend build/deployment pipeline, but it is not a production authentication architecture.

## 7. Implemented versus future work

| Capability | Current state |
|---|---|
| Inventory and declared-profile posture | Implemented prototype |
| Evidence ingestion and listing | Implemented prototype |
| Selected-attribute normalization projection | Implemented prototype |
| Automatic device association/conflict resolution | Not implemented |
| Evidence-driven posture | Not implemented |
| Bounded CycloneDX ingestion | Implemented prototype |
| Product-release SBOM import comparison by unique PURL identity | Implemented prototype; ambiguous and PURL-less components remain unmatched |
| Synthetic local advisory matching | Implemented demo behavior |
| Optional OSV lookup | Best-effort integration |
| Justified vulnerability triage | Implemented prototype |
| JSON/Markdown reports | Implemented prototype |
| Hash-chain verification | Implemented with limitations |
| Individual identity/RBAC/tenant isolation | Not implemented |
| External audit anchoring and immutable retention | Not implemented |

## 8. Where to verify behavior

- Routes and orchestration: `app/main.py`
- Request constraints: `app/schemas.py`
- Persistence: `app/db.py`
- Posture rules: `app/posture.py`
- SBOM parsing and matching: `app/sbom.py`
- Product SBOM persistence and comparison: `app/product_sbom.py`
- Evidence normalization: `app/evidence_normalization.py`
- Audit hashing: `app/audit.py`
- Tests: `tests/`

Related documents: [Engineering decisions](engineering-decisions.md), [Threat model](threat-model.md), [Security controls](security-controls.md).
