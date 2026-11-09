# Roadmap

This roadmap separates implemented prototype capabilities from proposed work. A planned item is not an implemented feature. The strategic hypothesis is described in [Market Positioning](market-positioning.md): small and medium-sized manufacturers of connected and embedded products are the initial customer segment to validate; consultancies and integrators are complementary users. The food-processing / cold-chain scenario remains a synthetic demonstration context.

## Milestone 0 — Existing engineering baseline

- [x] Establish the Python/FastAPI application and SQLAlchemy persistence.
- [x] Document architecture, trust boundaries and prototype limitations.
- [x] Add CI quality/security checks and CodeQL configuration.
- [x] Keep changes reviewable through focused branches and pull requests.

## Milestone 1 — Current inventory and assessment prototype

- [x] Store device inventory and declared security attributes.
- [x] Assess selected declared controls and expose posture findings.
- [x] Preserve unknown states instead of treating missing fields as safe.
- [x] Store bounded evidence observations with source and timestamps.
- [x] Parse a bounded CycloneDX JSON subset and validate supported PURLs.
- [x] Match components against synthetic local demonstration advisories.
- [x] Support optional best-effort OSV lookup.
- [x] Record vulnerability-triage decisions with mandatory justification.
- [x] Generate JSON/Markdown reports and verify the SHA-256-linked audit history.
- [x] Provide a same-origin local operator console.

## Milestone 2 — Database migration foundation (P0)

**Goal:** make schema evolution explicit and establish a tested PostgreSQL persistence path before adding new domain entities.

- [x] Add Alembic configuration and an initial migration matching the current SQLAlchemy schema.
- [x] Remove runtime `create_all()` from application startup.
- [x] Apply migrations explicitly in local, container-startup and demo-seeder workflows.
- [x] Add SQLite migration upgrade/downgrade and ORM metadata-drift tests.
- [x] Add PostgreSQL CI coverage, including persistence after engine disposal and reconnection.
- [x] Document safe adoption of legacy SQLite databases through backup, schema verification and explicit baseline stamping.
- [ ] Verify PostgreSQL startup, persistence and restart behavior in a clean local Compose deployment.
- [ ] Demonstrate backup/restore and deployment rollback.
- [ ] Validate the legacy SQLite adoption procedure against a preserved copy of a real pre-Alembic database.

**Exit criteria:** automated migration and PostgreSQL persistence checks pass on the candidate commit; local Compose, legacy-database adoption and recovery procedures are separately evidenced before a versioned release.

Product/version/component domain modelling is intentionally tracked in Milestone 3 rather than being treated as completed by the database foundation.

## Milestone 3 — Persistent SBOM and component intelligence (P1)

**Goal:** answer which product releases may contain a newly affected component.

- [x] Persist accepted CycloneDX JSON 1.5 SBOM imports with format, spec version, source, timestamp, SHA-256 digest and parser version.
- [x] Persist component occurrences and link them to a specific product release and SBOM import.
- [x] Preserve source component name/version values and supported PURLs without inventing identifiers.
- [x] Add duplicate detection and idempotent re-import behavior for the same release, format and content digest.
- [x] Link synthetic vulnerability findings to exact component occurrences.
- [x] Compare accepted SBOM imports and explain additions, removals and matched-component changes using PURL identity that excludes only the version segment while preserving qualifiers and subpath; report ambiguous and unidentified occurrences without speculative matching.
- [ ] Re-evaluate stored product releases when vulnerability intelligence changes.

**Implemented:** PR #45 was merged into main. It adds append-only assessment runs and findings for an accepted SBOM import, reuses the bounded local/OSV scanner, records enrichment coverage, and persists the run with its audit event after external I/O. KEV/EPSS enrichment is tracked separately in PR #47 and remains pending merge.
- [ ] Expand beyond the currently supported CycloneDX JSON 1.5 subset and expose unsupported fields more comprehensively.

**Current status:** the initial persistence slice is implemented and merged in PR #22. It supports bounded CycloneDX JSON 1.5 imports, product-release association, component occurrences, source/digest/parser metadata, idempotent duplicate handling and component-scoped synthetic findings. It now includes read-only comparison of accepted imports for the same release. Duplicate identities and components without usable PURLs remain unresolved. Comparison does not re-evaluate vulnerability intelligence.

**Remaining exit criteria:** stored product releases can be re-evaluated when intelligence changes, with broader format/field coverage and ecosystem-aware version semantics implemented and tested.

## Milestone 4 — Reviewed vulnerability decisions and intelligence (P2)

**Goal:** provide explainable product-version impact assessments, not automatic compliance conclusions.

- [ ] Merge and release the bounded CISA KEV enrichment proposed in [PR #47](https://github.com/silvatechf/DeviceTrust/pull/47), retaining source, retrieval timestamp and catalog metadata.
- [ ] Merge and release the bounded FIRST EPSS enrichment proposed in [PR #47](https://github.com/silvatechf/DeviceTrust/pull/47), retaining score, model/date metadata and retrieval timestamp.
- [ ] Preserve feed provenance, freshness and lookup failures; missing intelligence must not mean no risk.
- [ ] Match findings against product/component versions with ecosystem-aware semantics and explicit uncertainty.
- [ ] Add human-reviewed affected/not-affected decisions with evidence and rationale.
- [ ] Implement CycloneDX VEX export only after product/version/component relationships and review controls exist.
- [ ] Map internal workflow states explicitly to the selected VEX vocabulary; never equate operational triage states directly with VEX statements.
- [ ] Consider OpenVEX only after the CycloneDX workflow is stable.
- [ ] Treat KEV and EPSS as prioritisation signals, not automatic CRA Article 14 triggers.
- [ ] Support reviewed reporting drafts only; no automatic legal timer or ENISA submission.

**Exit criteria:** every exported VEX statement is product-version scoped, attributable and justified; no unsupported not_affected claim can be emitted.

## Milestone 5 — Developer workflow and ecosystem support (P3)

**Goal:** make the assessment workflow usable in engineering pipelines without duplicating business logic.

- [ ] Add a CLI that calls the same application/domain services as the API.
- [ ] Define stable machine-readable output and documented exit codes.
- [ ] Fail closed or return an explicit incomplete/error state when required intelligence is unavailable.
- [ ] Add a GitHub Action after the CLI contract is stable.
- [ ] Evaluate SPDX ingestion after the canonical component model is established.
- [ ] Test common embedded/Yocto SBOM cases and document identifier gaps, backports and vendor modifications.
- [ ] Provide synthetic fixtures and integration tests for pipeline usage.

**Exit criteria:** CLI and API produce consistent assessments; pipeline results distinguish policy findings from assessment/runtime errors and incomplete intelligence.

## Milestone 6 — Identity, governance and audit assurance (P2 prerequisite)

**Goal:** prepare for attributable multi-user and controlled customer evaluation.

- [ ] Implement individual identities, credential lifecycle, revocation and scoped authorization.
- [ ] Add RBAC and tenant isolation before multi-customer operation.
- [ ] Record actor identity, decision, rationale and evidence references for every security decision.
- [ ] Add a durable audit checkpoint design with protected signing keys and independently stored checkpoints. Transactional writer serialization does not replace this independent trust boundary.
- [x] Serialize concurrent audit-chain updates and test tampering, deletion and transaction rollback scenarios.
- [ ] Define retention, backup/restore, operational monitoring, rate limits and deployment hardening.
- [ ] Create an exportable Product Security File as a product concept, with clear provenance and limitations.
- [ ] Prepare reviewed CRA reporting data only where a manufacturer has established the applicable reporting condition and authorised the action.

**Exit criteria:** no shared credential for multi-user operation; decisions are attributable; audit checkpoints have an independent trust boundary; tenant isolation and operational recovery are tested.

## Milestone 7 — Credential exposure evidence (P3, proposed)

**Goal:** correlate externally detected credential-exposure signals with product releases and retain safe, attributable remediation evidence.

- [ ] Select one supported secret-scanning report contract (initial candidate: sanitised Gitleaks CI output) and pin/version its parser contract.
- [ ] Define a bounded ingestion schema for tool/rule, source, artifact digest, sanitised location, observation time and coverage metadata.
- [ ] Prove that raw API keys, passwords, JWT material, database URLs, RTSP/ONVIF credentials and private keys never enter persistence, API responses, logs or audit events.
- [ ] Associate findings only with explicitly declared product/release/artifact references; retain ambiguous or missing relationships as unassigned.
- [ ] Preserve immutable scan observations, provenance, idempotency and explicit incomplete/unverified states.
- [ ] Add attributable review and remediation evidence only after individual identity, scoped authorisation and audit attribution are available.
- [ ] Evaluate PKI, mTLS and secret-manager metadata integrations as evidence sources; do not store private keys or secret values.
- [ ] Keep credential testing, endpoint discovery, video retrieval, automatic rotation/revocation and network enforcement outside DeviceTrust.

**Dependency:** identity and scoped-authorisation foundations in Milestone 6 are prerequisites for reviewed decisions and remediation attribution. This milestone begins with safe, read-only evidence ingestion; it does not create a secret vault or scanner.

**Exit criteria:** scanner evidence is bounded, provenance-preserving and demonstrably secret-free in storage/logs/responses; ambiguous product relationships remain unresolved; reviewed remediation is attributable and auditable.

## Parallel product discovery

- [ ] Conduct 5–10 exploratory interviews with small and medium-sized connected-product manufacturers.
- [ ] Interview product-security consultancies and specialist integrators as complementary users/channels.
- [ ] Validate the product/version/component traceability problem before broad implementation.
- [ ] Identify a budget owner and a partner willing to run a bounded pilot with authorised data.
- [ ] Revisit the target segment if interviews contradict the manufacturer hypothesis.

## Explicit non-goals for the current roadmap

- No SaaS or multi-tenant deployment before identity and tenant-isolation foundations.
- No autonomous remediation or physical equipment control.
- No claim of CRA compliance, certification or automatic regulatory reporting.
- No replacement of full SCA, PSIRT, OT monitoring or vulnerability-management platforms.
- No microservices split without demonstrated scaling or ownership pressure.

See [Release readiness](release-readiness.md) for evidence required before a public versioned release.
