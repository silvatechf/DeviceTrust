# Architecture and Visual Technical Reference

**Documentation status:** diagrams describe the current repository implementation at the time of this change. They are editable Mermaid source, not runtime screenshots or operational evidence.

## 1. System architecture

DeviceTrust is a modular monolith. HTTP requests enter FastAPI, authentication dependencies and request validation are resolved at the API boundary, route handlers coordinate domain services, and SQLAlchemy persists device, vulnerability and audit records. Typed endpoints use the Pydantic models in `app/schemas.py`; the SBOM endpoint accepts a raw `Request` and applies bounded JSON and CycloneDX validation explicitly.

```mermaid
flowchart TB
    C["API client / operator"] -->|"HTTPS deployment-dependent; X-API-Key"| API["FastAPI application"]
    API --> AUTH["Shared API-key dependency"]
    AUTH --> VALID["FastAPI request validation boundary"]
    VALID --> ROUTES["HTTP route handlers"]
    VALID -.-> SCHEMA["Pydantic models for typed endpoints"]
    ROUTES --> POSTURE["Posture assessment service"]
    ROUTES --> SBOM["SBOM parser and matching service"]
    SBOM --> SBOMVALID["Manual bounded JSON / CycloneDX validation"]
    ROUTES --> TRIAGE["Vulnerability triage"]
    ROUTES --> AUDIT["Audit service"]
    ROUTES --> REPORT["JSON / Markdown report assembly"]
    ROUTES --> ORM["SQLAlchemy session"]
    POSTURE --> ROUTES
    SBOM -->|"Optional outbound query when DEVICETRUST_OSV=1"| OSV["OSV API"]
    ORM --> DB[("SQLite by default / PostgreSQL via DATABASE_URL")]
    AUDIT --> ORM
    REPORT --> ORM
```

### Component responsibilities

| Component | Current responsibility | Implementation |
|---|---|---|
| API boundary | Authentication, request handling and response serialization | `app/main.py` |
| Input contracts | Strict Pydantic schemas and bounded fields | `app/schemas.py` |
| Device persistence | Device inventory and declared security profile | `app/db.py` |
| Posture service | Evidence-based control findings and risk summary | `app/posture.py` |
| SBOM service | Bounded CycloneDX component parsing, PURL validation and optional OSV lookup | `app/sbom.py` |
| Triage | Status and mandatory justification for vulnerability decisions | `app/main.py`, `app/schemas.py` |
| Audit | SHA-256 hash-linked event records and verification | `app/audit.py` |
| Reporting | Per-device posture, vulnerability and evidence-trail report | `app/main.py` |

## 2. Trust boundaries and attack surfaces

```mermaid
flowchart LR
    subgraph EXT["Untrusted external boundary"]
      CLIENT["API client"]
      BOM["Uploaded SBOM JSON"]
    end
    subgraph APP["Application trust boundary"]
      AUTH["Shared API-key check"]
      VALID["Bounded JSON / CycloneDX / PURL validation"]
      ROUTE["FastAPI routes and domain services"]
      DB[("Application database")]
    end
    subgraph THIRD["External service boundary"]
      OSV["OSV API"]
    end
    CLIENT -->|"Credential-bearing HTTP request"| AUTH
    AUTH --> ROUTE
    BOM -->|"2 MiB streaming cap; JSON parsing"| VALID
    VALID --> ROUTE
    ROUTE --> DB
    ROUTE -->|"Optional, version-scoped request"| OSV
    OSV -->|"Best-effort response; errors skipped"| ROUTE
```

**Security interpretation**

- The API uses one shared `DEVICETRUST_API_KEY`; it is not user identity, role-based authorization or tenant isolation.
- Missing server-side API-key configuration fails closed with HTTP 503; a wrong key receives HTTP 401.
- SBOM input is untrusted. The endpoint reads a raw request body capped at 2 MiB, then manually validates JSON and a bounded subset of CycloneDX components; it does not use a dedicated Pydantic SBOM request model.
- Device security and management-interface attributes are declared evidence. DeviceTrust does not independently probe device reachability or attest that submitted claims are true.
- OSV is an optional external dependency. Network and response errors are skipped; a missing result is not proof that a component is safe.
- The database is inside the application trust boundary. The current audit hash chain does not provide immutable/WORM storage or an external checkpoint.

## 3. Device security posture assessment

```mermaid
flowchart TD
    START["GET /devices/{id}/posture or report"] --> LOAD["Load device and declared security profile"]
    LOAD --> EVAL["Evaluate modeled controls in app/posture.py"]
    EVAL --> ID["Device identity and authentication"]
    EVAL --> CFG["Default credentials and insecure interfaces"]
    EVAL --> NET["Device and management-plane exposure"]
    EVAL --> DATA["Encryption in transit / at rest"]
    EVAL --> UPDATE["Update mechanism and support date"]
    EVAL --> LOG["Security logging"]
    EVAL --> INTEGRITY["Secure boot and firmware signing"]
    ID --> AGG["Aggregate control findings"]
    CFG --> AGG
    NET --> AGG
    DATA --> AGG
    UPDATE --> AGG
    LOG --> AGG
    INTEGRITY --> AGG
    AGG --> SUMMARY["Status counts, highest risk, evidence coverage"]
    SUMMARY --> OUT["Return posture / include in report"]
```

Each modeled control returns a status such as `compliant`, `partial`, `non_compliant` or `unverified`. Missing evidence is not treated as compliance. The assessment uses declared metadata; it is not a device scan, safety interlock or CRA conformity assessment.

## 4. SBOM ingestion and vulnerability workflow

```mermaid
flowchart TD
    REQ["POST /devices/{id}/sbom"] --> AUTH["Shared API-key authentication"]
    AUTH --> CAP["Stream request body; reject above 2 MiB"]
    CAP --> JSON["Decode UTF-8 JSON; require object"]
    JSON --> CYCLONE["Require bomFormat = CycloneDX and components array"]
    CYCLONE --> BOUNDS["Enforce component count and field length bounds"]
    BOUNDS --> PURL["Validate component object, name, version and optional PURL"]
    PURL --> NORMAL["Normalize component identity"]
    NORMAL --> LOCAL["Local demo advisory match: PURL type/name + version comparison"]
    NORMAL --> FLAG{"DEVICETRUST_OSV = 1?"}
    FLAG -->|"Yes"| OSV["Optional OSV query by PURL and exact version"]
    FLAG -->|"No"| MERGE["Combine findings"]
    OSV --> MERGE
    LOCAL --> MERGE
    MERGE --> DEDUPE["Avoid duplicate device/component/version/vulnerability records"]
    DEDUPE --> SAVE["Persist vulnerability findings"]
    SAVE --> EVENT["Record sbom.import audit event"]
    EVENT --> COMMIT["Commit transaction"]
    COMMIT --> RESPONSE["Return component and new-finding counts"]
    SAVE --> LIST["GET /devices/{id}/vulnerabilities"]
    LIST --> TRIAGE["PATCH /vulnerabilities/{id}: status + justification"]
    TRIAGE --> TRIAGE_EVENT["Record vulnerability.triage audit event"]
```

**Important boundaries**

- The local `DT-DEMO-*` advisory file is synthetic demonstration data, not a vulnerability feed.
- Local matching requires PURL package type/name identity and a version comparison; components without a PURL are not matched against the local demo records.
- CycloneDX validation covers a bounded subset, not the complete specification or dependency graph.
- OSV lookup is opt-in and best-effort. It does not persist full affected-range provenance.
- Triage supports `open`, `in_progress`, `fixed`, `accepted_risk` and `not_affected`; the request requires a justification of at least 10 characters.

## 5. Audit event and hash-chain flow

```mermaid
flowchart TD
    MUTATION["State-changing operation"] --> EVENT["Build audit event: timestamp, actor, action, entity, payload"]
    EVENT --> HEAD["Read latest stored audit entry"]
    HEAD --> PREV["Use previous entry hash; genesis is 64 zeroes"]
    PREV --> HASH["SHA-256 over canonicalized event data and previous hash"]
    HASH --> STORE["Insert event with prev_hash and hash"]
    STORE --> TX["Commit with application transaction"]
    VERIFY["GET /audit/verify"] --> ORDER["Read entries by ascending ID"]
    ORDER --> CHECK["Recompute each hash and compare prev_hash linkage"]
    CHECK --> RESULT["Return valid flag, entry count and first broken ID"]
```

The chain detects mutation or gaps that break a retained link. It cannot detect deletion of the final entry or final suffix without an independently retained checkpoint. A privileged database actor may rewrite records and recompute the chain. Concurrent writers are not serialized by an external chain-head mechanism.

## 6. CI / DevSecOps pipeline

```mermaid
flowchart TD
    CHANGE["Push or pull request"] --> RUNNER["GitHub Actions: Ubuntu + Python 3.12"]
    RUNNER --> INSTALL["Install requirements-dev.txt"]
    INSTALL --> RUFF["Ruff lint"]
    RUFF --> BANDIT["Bandit source security scan"]
    BANDIT --> AUDIT["pip-audit runtime dependency audit"]
    AUDIT --> TEST["pytest"]
    TEST --> RESULT["Workflow success / failure"]
```

The workflow runs on pushes, pull requests and manual dispatch. The checks are automated validation gates; they do not prove absence of vulnerabilities or replace human review.

## 7. Implemented versus planned

| Capability | Status represented by this architecture |
|---|---|
| Device inventory and declared security profile | Implemented prototype |
| Evidence-based posture assessment | Implemented prototype |
| CycloneDX bounded-subset ingestion | Implemented prototype |
| Local PURL-scoped advisory matching | Synthetic demo implementation |
| Optional version-scoped OSV lookup | Implemented, best-effort |
| Vulnerability triage with justification | Implemented prototype |
| JSON and Markdown reports | Implemented prototype |
| Hash-chain audit verification | Implemented with documented limitations |
| CISA KEV enrichment, event monitoring, lifecycle intelligence | Planned |
| RBAC, tenant isolation, external audit checkpoints | Not implemented |

## 8. Source-of-truth map

- API routes and request orchestration: `app/main.py`
- Input validation: `app/schemas.py`
- Persistence models and database configuration: `app/db.py`
- Posture rules: `app/posture.py`
- SBOM parsing and vulnerability matching: `app/sbom.py`
- Audit event hashing and verification: `app/audit.py`
- Security control mapping: [Security controls and evidence](security-controls.md)
- Abuse cases and residual risks: [Threat model](threat-model.md)
- Known prototype boundaries: [Prototype limitations](prototype-limitations.md)
