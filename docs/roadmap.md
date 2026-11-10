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
- [x] Preserve CycloneDX serialNumber, BOM version, metadata.component identity and supplied top-level component bom-ref values for future VEX linkage. See [DEC-011](decisions/DEC-011-cyclonedx-reference-preservation.md).
- [x] Add duplicate detection and idempotent re-import behavior for the same release, format and content digest.
- [x] Link synthetic vulnerability findings to exact component occurrences.
- [x] Compare accepted SBOM imports and explain additions, removals and matched-component changes using PURL identity that excludes only the version segment while preserving qualifiers and subpath; report ambiguous and unidentified occurrences without speculative matching.
- [x] Re-evaluate all accepted SBOM imports for a product release through an authenticated, resumable API workflow. Each import receives an independent append-only assessment run; repeated requests with the same idempotency key do not duplicate completed runs. See `POST /product-releases/{release_id}/assessments`.
- [x] Compare matched PyPI PURL versions with conservative PEP 440 semantics; unsupported ecosystems and invalid versions remain explicitly `unknown` (PR #69).

**Implemented:** PR #45 added append-only assessment runs and findings for accepted SBOM imports, reuses the bounded local/OSV scanner, records enrichment coverage, and persists each run with its audit event after external I/O.
- [ ] Expand beyond the currently supported CycloneDX JSON 1.5 subset and expose unsupported fields more comprehensively.

**Current status:** the initial persistence slice is implemented and merged in PR #22. It supports bounded CycloneDX JSON 1.5 imports, product-release association, component occurrences, source/digest/parser metadata, idempotent duplicate handling and component-scoped findings. PR #68 added resumable release-wide reassessment. PR #69 added a conservative PyPI/PEP 440 comparator. Duplicate identities and components without usable PURLs remain unresolved. Comparison does not re-evaluate vulnerability intelligence.

**Remaining exit criteria:** broaden format/field coverage and add native version semantics for ecosystems beyond the initial PyPI/PEP 440 adapter. Vendor backport handling and source/binary package relationships remain open. Release-wide reassessment is on-demand; scheduling and automatic triggers on feed changes are not implemented.

## Milestone 4 — Reviewed vulnerability decisions and intelligence (P2)

**Goal:** provide explainable product-version impact assessments, not automatic compliance conclusions.

- [x] Add CISA KEV enrichment with source, retrieval timestamp and catalog metadata. See implemented [DEC-009](decisions/DEC-009-kev-epss-enrichment.md).
- [x] Add FIRST EPSS enrichment with score, model/date metadata and retrieval timestamp. See implemented [DEC-009](decisions/DEC-009-kev-epss-enrichment.md).
- [x] Preserve feed provenance, freshness and lookup failures; missing intelligence must not mean no risk.
- [x] Preserve source-aware applicability evidence for OSV package/version matches and synthetic demo candidates, with explicit uncertainty. See [DEC-010](decisions/DEC-010-source-aware-applicability.md) and PR #53.
- [x] Add conservative PEP 440 version comparison for matched PyPI PURLs; unsupported ecosystems and invalid versions remain explicitly unknown.
- [ ] Add native Debian/RPM/npm/Maven/Go version semantics, vendor backport handling and source/binary package relationships beyond OSV provider matching.
- [x] Add attributable, append-only human-reviewed vulnerability decisions linked to immutable assessment findings; require CycloneDX justification and evidence for not_affected. See [DEC-012](decisions/DEC-012-attributable-vulnerability-review.md).
- [x] Implement deterministic CycloneDX 1.5 VEX export for one completed assessment, with fail-closed eligibility, current signature/approval/manifest verification, dedicated managed scope and vendored-schema validation (PR #72).
- [x] Define explicit mapping from reviewed decision states to CycloneDX 1.5 analysis vocabulary and prohibit mapping provider/applicability signals directly to VEX decisions (DEC-013).
- [ ] Consider OpenVEX only after the CycloneDX workflow is stable.
- [ ] Treat KEV and EPSS as prioritisation signals, not automatic CRA Article 14 triggers.
- [ ] Support reviewed reporting drafts only; no automatic legal timer or ENISA submission.

**Exit criteria:** every exported VEX statement is product-version scoped, attributable and justified; no unsupported not_affected claim can be emitted. Review records, detached decision signatures, independent second-person approval, observation-linked artifact byte integrity and decision-revision manifest binding are integrated through PRs #56, #58, #62, #64 and #65. Source authentication and external audit anchoring remain open. The first conservative VEX export slice is implemented in PR #72; broader VEX workflows and external publication remain deferred.

## Milestone 5 — Developer workflow and ecosystem support (P3)

**Goal:** make the assessment workflow usable in engineering pipelines without duplicating business logic.

- [x] Add an authenticated CLI client that calls the existing API and preserves its authorization boundary (PR #67).
- [x] Define stable JSON output, structured errors and documented process exit codes (PR #67).
- [x] Preserve explicit incomplete assessment states and distinguish API/runtime errors from successful findings (PR #67; existing assessment contract).
- [ ] Add a GitHub Action after the CLI contract is stable.
- [ ] Evaluate SPDX ingestion after the canonical component model is established.
- [ ] Test common embedded/Yocto SBOM cases and document identifier gaps, backports and vendor modifications.
- [ ] Provide synthetic fixtures and integration tests for pipeline usage.

**Current status:** the authenticated `assess`, `history` and `findings` CLI commands are implemented as a thin HTTP client; they do not open the database or duplicate assessment logic.

**Exit criteria:** CLI and API continue to share the same assessment contract; a future pipeline integration must distinguish policy findings from assessment/runtime errors and incomplete intelligence.

## Milestone 6 — Identity, governance and audit assurance (P2)

**Goal:** establish attributable API access and least-privilege operator workflows before reviewed VEX decisions or credential-exposure evidence are introduced.

**Architecture and implementation:** [Identity and Access Governance](identity-access-governance.md) documents the implemented managed API credential foundation and its remaining boundaries. Managed mode is opt-in; legacy shared-key mode remains the backwards-compatible default.

- [x] Add operator/service principals and independently revocable API credentials with bounded expiry.
- [x] Store only keyed HMAC-SHA256 verifiers for high-entropy machine tokens using an external pepper; show raw tokens once through the offline CLI.
- [x] Enforce explicit route-level scopes and fail closed when a protected route has no policy.
- [x] Add offline principal creation, credential issuance/rotation/revocation and principal disablement.
- [x] Attribute managed API requests to stable principal IDs while preserving historical audit hashes and actor values.
- [ ] Migrate deployments from legacy shared-key mode to managed mode using documented client/deployment evidence.
- [ ] Add human identity proof, MFA/SSO only when operator/customer requirements justify it.
- [ ] Add RBAC and tenant isolation before multi-customer operation.
- [ ] Record actor identity, decision, rationale and evidence references for every reviewed security decision.
- [ ] Add a durable audit checkpoint design with protected signing keys and independently stored checkpoints. Transactional writer serialization does not replace this independent trust boundary.
- [x] Serialize concurrent audit-chain updates and test tampering, deletion and transaction rollback scenarios.
- [x] Add bounded evidence artifact storage linked to observations, server-computed SHA-256 and byte-length verification, fail-closed downloads and transactional audit metadata (integrated into `main` through PR #64).
- [x] Bind immutable evidence artifact manifests to exact vulnerability decision revisions and include the manifest digest in decision-signature and approval envelope v2 (integrated into `main` through PR #65; exact-head CI and security checks passed).
- [ ] Add artifact source authentication, optional evidence-signature verification and a documented evidence trust policy.
- [ ] Define retention, backup/restore, operational monitoring, rate limits and deployment hardening.
- [ ] Create an exportable Product Security File as a product concept, with clear provenance and limitations.
- [ ] Prepare reviewed CRA reporting data only where a manufacturer has established the applicable reporting condition and authorised the action.

**Exit criteria:** managed credentials are individually revocable and scoped; mutating managed API actions are attributable; historical audit hashes remain valid; legacy shared-key mode is retired before multi-user operation; tenant isolation and operational recovery are tested before multi-customer use.

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


## Product delivery sequence — phase gates

The strategic direction and customer/problem hypotheses are maintained in [Product Vision](product-vision.md). This section prioritises delivery across the existing milestones; it does not mark planned work as implemented.

### P0 — Consolidate the current workflow
- [ ] Complete and merge authenticated CLI SBOM import only after exact-head checks and review.
- [ ] Verify the full API sequence: product/release, SBOM import, assessment, findings, decision, evidence manifest, signature, independent approval, VEX and history.
- [ ] Keep README, test matrix, API contracts and continuity record consistent with the verified implementation.
- **Gate:** reproducible API/CLI walkthrough with known limitations and validation evidence.

### P1 — Demonstrable operator workflow
- [ ] Build one synthetic product/release vertical slice on existing API contracts.
- [ ] Implement a minimal operator UI; avoid dashboards and broad administration.
- [ ] Cover import through VEX/history, including fail-closed negative cases.
- [ ] Add end-to-end coverage and a clean runbook.
- **Gate:** operator completes the core demonstration without manually composing HTTP requests; critical transitions are tested.

### P2 — Intelligence quality
- [ ] Add representative real-world (authorised) and synthetic SBOM fixtures.
- [ ] Expand ecosystem-specific PURL/version semantics only where fixtures and user evidence justify it.
- [ ] Document coverage, unsupported cases, vendor backports and source/binary limitations.
- [ ] Evaluate additional intelligence sources and SPDX after canonical component semantics are stable.
- **Gate:** tested version edge cases and transparent coverage; no speculative matching.

### P3 — Interoperability and independent trust
- [ ] Evaluate OpenVEX after the CycloneDX workflow is stable.
- [ ] Evaluate upstream VEX/CSAF only against a concrete integration need.
- [ ] Select at most one first external audit checkpoint design (e.g. RFC 3161 or Merkle-based checkpoint).
- [ ] Evaluate DSSE only when a named consumer or ecosystem requires it.
- **Gate:** independently verifiable exchange/checkpoint with documented trust and operational ownership.

### P4 — Multi-team operations
- [ ] Define reassessment scheduling, decision expiry/review and notification semantics.
- [ ] Add human identity, MFA/SSO, RBAC and tenant isolation before multi-customer operation.
- [ ] Evidence backup/restore, monitoring, rate limiting, incident response and deployment rollback.
- [ ] Keep firmware SBOM discovery as a separate research track.
- **Gate:** security and operational controls tested in the intended deployment model.

### Parallel discovery and success measures
- [ ] Complete 5–10 interviews with target manufacturers; include consultancies/integrators as complementary perspectives.
- [ ] Identify a recurring workflow, a budget owner and a credible bounded-pilot path before broadening scope.
- [ ] Target a reproducible end-to-end demo under 10 minutes.
- [ ] Ensure every VEX export is tied to a release, assessment and reviewed decision; required approval/evidence gates must fail closed.
- [ ] Record coverage and unknown states explicitly.

Phases are acceptance-gated, not date-driven. Do not interpret these targets as achieved results. CRA compliance, conformity assessment, automatic regulatory reporting, active discovery, IDS/IPS, autonomous remediation and premature multi-tenancy remain explicit non-goals.
