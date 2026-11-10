# Architecture

## 1. Design in one sentence

DeviceTrust is a Python modular monolith: FastAPI exposes the HTTP API, domain modules implement posture/SBOM/audit behavior, and SQLAlchemy persists the records.

It is deliberately a single application. The current scope does not justify the operational cost of microservices.

## 2. Request flow

```mermaid
flowchart TD
    CLIENT[API client / local console] --> API[FastAPI route]
    API --> AUTH[Legacy key / managed scoped token]
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
| `app/identity.py` | Principal/credential verification, route-scope policy and credential lifecycle operations |
| `app/identity_cli.py` | Offline principal creation, credential issuance/rotation/revocation and principal disablement |\n| `app/cli.py` | Authenticated HTTP client for versioned SBOM assessment, history and findings; preserves API authorization and emits machine-readable JSON |
| `app/applicability.py` | Source-aware classification of versioned findings without inferring VEX or `not_affected` decisions |
| `app/vulnerability_decisions.py` | Append-only, attributable human review history for immutable assessment findings |
| `app/schemas.py` | Pydantic request contracts and field constraints |
| `app/db.py` | SQLAlchemy models, engine/session setup and database access |
| `app/posture.py` | Rules that assess the declared device security profile |
| `app/sbom.py` | CycloneDX subset parsing, PURL validation, local demo matching and optional OSV lookup |
| `app/evidence_normalization.py` | Pure normalizers for selected evidence attributes |
| `app/audit.py` | Transaction-serialized SHA-256 audit appends and chain verification |
| `web/` | Static same-origin operator console |

Routes coordinate work; domain rules should remain in their relevant modules rather than growing inside route handlers.

## 4. Data flows

### Device posture

The posture service evaluates declared fields such as authentication, encryption, update mechanism, secure boot and internet exposure. Missing fields produce `unverified` findings. The input is declared metadata, not a measurement collected from the device.

### Evidence observations

```mermaid
flowchart TD
    SOURCE[External or manual source] --> POST[POST /evidence]
    POST --> AUTH[Authentication mode and route scope check]
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

The API caps the request body at 2 MiB. The parser accepts a bounded CycloneDX JSON subset, validates component names/versions and PURLs, then checks the local synthetic advisory set. If `DEVICETRUST_OSV=1`, product-scoped imports also perform best-effort OSV enrichment, deduplicated by versionless PURL plus the exact component version and bounded to 50 unique queries and one absolute, cancellable 10-second wall-clock deadline covering query preparation and awaited OSV I/O. Cancellation is cooperative and cannot pre-empt synchronous CPU work. The OSV request uses a versionless PURL and a separate top-level version, preserving qualifiers and subpath. The persisted import summary records source, timestamp, counts and `complete`/`incomplete`/`disabled` status. Failures, malformed responses, deadline/query-budget exhaustion and components without PURLs are explicitly incomplete; a missing finding is not proof that a component is safe.

Versioned assessment findings retain separate source-aware applicability signals: OSV provider matches are recorded as `osv_reported_affected`, synthetic demo matches as `synthetic_candidate`, and malformed/unsupported evidence as `unknown`. No-match or missing findings never create a `not_affected` conclusion. Managed operator principals can append review decisions to exact assessment findings; each revision retains its predecessor, rationale, evidence references and audit attribution. A not_affected decision requires a CycloneDX justification and evidence reference. See [DEC-010](decisions/DEC-010-source-aware-applicability.md), [DEC-011](decisions/DEC-011-cyclonedx-reference-preservation.md) and [DEC-012](decisions/DEC-012-attributable-vulnerability-review.md). This workflow does not yet export VEX.

### Product SBOM comparison

The authenticated `GET /product-releases/{release_id}/sbom/diff` endpoint compares two accepted imports belonging to the same product release. It removes only the PURL version segment when constructing component identity; qualifiers and subpath remain identity boundaries. Additions and removals are reported separately. Matched components with changes appear once with a `changes` array containing `version`, `name`, or both. Duplicate identities are reported as ambiguous. Components without a usable PURL remain unidentified and are never matched by name or ordinal. The comparison is read-only and does not re-evaluate vulnerability findings. PURL identity does not prove artifact or supplier equivalence.

### Release-wide reassessment\n\nThe authenticated `POST /product-releases/{release_id}/assessments` endpoint enumerates up to 100 accepted SBOM imports for a release and invokes the existing versioned assessment workflow for each import. Each import commits independently and receives a deterministic idempotency key derived from the release request key and import ID. Repeating the same request retrieves completed runs without duplicating them; a partial response identifies imports that failed so the caller can retry safely. Assessment findings remain append-only. This is an on-demand API operation, not a scheduled feed-change watcher.\n\n### Triage and audit

A triage update requires a justification. State-changing operations append audit entries in the same database transaction as the domain mutation. Authenticated write requests acquire the singleton audit-chain state row before database reads; PostgreSQL serializes through the row update lock, while SQLite starts an IMMEDIATE write transaction. Both backends use a 10-second lock wait bound. The lock is held until commit or rollback, so concurrent application writers sharing the same database cannot append from the same chain head. Each entry hashes its content and the previous entry hash. The chain has no external checkpoint and is not immutable storage.

## 5. Trust boundaries

- API clients are untrusted; protected routes use an explicit authentication mode and route-level authorization policy.
- Legacy mode uses one shared API key and remains the backwards-compatible default. Managed mode validates individual API credentials against principal state and required scopes.
- Uploaded SBOM and evidence values are untrusted input.
- Evidence references are opaque; the application does not fetch them.
- Device security attributes are declarations and are not independently attested.
- OSV is an external dependency and is optional/best-effort.
- The database and audit chain share the same trust boundary; a privileged database attacker can rewrite both. Writer serialization does not provide independent tamper resistance.

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
| Synthetic local advisory matching | Implemented demo behavior |
| Optional OSV lookup | Best-effort integration; versionless PURL plus separate version query contract |
| Source-aware assessment applicability | Implemented prototype in PR #53; separate from human review decisions |
| Attributable vulnerability review history | Implemented prototype in the reviewed-decision branch; no VEX export |
| Justified vulnerability triage | Implemented prototype |
| JSON/Markdown reports | Implemented prototype |
| Hash-chain verification | Implemented with limitations |
| Individual managed API credentials and route scopes | Implemented prototype; offline CLI administration, legacy mode remains default |\n| Assessment CLI | Implemented API client; assess/history/findings commands with JSON output and stable exit codes |\n| Release-wide reassessment | Implemented on-demand API workflow; accepted imports assessed independently with resumable idempotency |
| Human login/MFA/SSO and tenant isolation | Not implemented |
| External audit anchoring and immutable retention | Not implemented; transactional writer serialization is not an external checkpoint |

## 8. Where to verify behavior

- Routes and orchestration: `app/main.py`
- Request constraints: `app/schemas.py`
- Persistence: `app/db.py`
- Posture rules: `app/posture.py`
- SBOM parsing and matching: `app/sbom.py`
- Evidence normalization: `app/evidence_normalization.py`
- Audit hashing: `app/audit.py`
- Tests: `tests/`

Related documents: [Engineering decisions](engineering-decisions.md), [Threat model](threat-model.md), [Security controls](security-controls.md).
