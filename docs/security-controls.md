# Security Controls

This document describes what the current code does, where to find its tests and what each control does not guarantee.

## Controls and limits

| Area | Current implementation | Test location | Limitation |
|---|---|---|---|
| API authentication and authorization | Legacy shared key remains available; managed mode verifies peppered HMAC-SHA256 API tokens, principal status, expiry and revocation, then enforces explicit route scopes | `tests/test_api.py`, `tests/test_identity.py`, `tests/test_postgres_persistence.py` | Legacy mode remains default; no human login/MFA/SSO or tenant isolation; credential administration is offline CLI only |
| Input validation | Pydantic schemas, strict extra-field handling and bounded fields | `tests/test_api.py` | No global rate limit or API gateway quota |
| Evidence observation ingestion | Source allowlist, bounded values, timezone-aware timestamps, opaque references and server-assigned `unverified` state | `tests/test_api.py` | No source-specific identity or independent attestation |
| Verification boundary | Server assigns `unverified`; client cannot self-verify | `tests/test_api.py` | No operator review workflow |
| Evidence artifact integrity | Bounded (1–5 MiB) database BLOBs linked to observations; server-computed SHA-256 and byte length; allow-listed declared media types; exact duplicate upload idempotency; transactional audit metadata; re-verification before download | `tests/test_evidence_artifacts.py`, `tests/test_migrations.py`, `tests/test_postgres_persistence.py` | Digest detects byte mismatch against stored metadata, not source authenticity or claim truth; privileged DB writers can replace both bytes and digest; no malware scanning, content sniffing or scalable object storage |
| SBOM body | Streaming 2 MiB limit; malformed/non-object JSON rejected | `tests/test_sbom_input_limits.py` | Reverse-proxy limits not validated |
| SBOM components | CycloneDX JSON `specVersion` 1.5 allow-list, component count/field bounds and PURL validation | `tests/test_sbom_validation.py` | Only version declaration is gated; not full CycloneDX schema or dependency-graph validation |
| Product/release SBOM API boundary | Legacy or managed authentication; managed routes require inventory/SBOM/assessment scopes as appropriate | `tests/test_api.py`, `tests/test_identity.py` | No tenant isolation or web-based credential administration |
| Product SBOM persistence and provenance | Accepted import metadata, exact-request-byte digest, release-scoped idempotency, component occurrences and component-scoped findings persist; audit append shares the import transaction | `tests/test_api.py`, `tests/test_sbom_persistence_models.py`, `tests/test_postgres_persistence.py` | Raw SBOM documents are not retained; no global component identity, cross-import deduplication or external provenance attestation |
| Product SBOM comparison | Authenticated, read-only comparison of two accepted imports from the same release; only PURL version is excluded from identity, while qualifiers and subpath are preserved | `tests/test_product_sbom_diff.py` | Duplicate, missing and invalid legacy PURLs remain unresolved; PURL identity does not prove artifact equivalence; no vulnerability re-evaluation |
| Versioned product SBOM reassessment (implemented in PR #45) | Authenticated append-only assessment runs with request-key idempotency, source-configuration fingerprinting, component-scoped findings and an audit append in the same transaction; original import findings and legacy triage remain separate | `tests/test_sbom_reassessment.py`, `tests/test_postgres_persistence.py` | Exact-head checks are required before claiming validation; OSV is best-effort; KEV/EPSS are prioritisation signals only; applicability signals do not replace human review or VEX |
| Local advisory matching | PURL package type/name and version-before-fixed comparison | `tests/test_sbom_validation.py` | Synthetic demo records, not a maintained feed |
| OSV lookup | Optional OSV query using an unversioned PURL plus a separate exact component version (the OSV API contract), deduplicated per import, capped at 50 unique queries and one absolute, cancellable 10-second wall-clock enrichment deadline covering query preparation and awaited OSV I/O; cancellation is cooperative and cannot pre-empt synchronous CPU work; explicit per-import coverage status is persisted | `tests/test_sbom_osv_response.py`, `tests/test_product_sbom_osv_enrichment.py` | Best-effort; timeouts, failures, budget exhaustion and components without valid PURLs produce `incomplete`; no result is not proof that a component is vulnerability-free |
| CycloneDX reference preservation (integrated through PR #55) | Persist top-level serialNumber/version, metadata component identity and optional component bom-ref; reject duplicate refs in the parsed top-level set | `tests/test_sbom_validation.py`, `tests/test_api.py`, `tests/test_migrations.py`, `tests/test_postgres_persistence.py` | Existing imports require identical-byte re-upload for audited metadata-only reprocessing; no VEX export; components without bom-ref remain unreferenced |
| Decision evidence manifest binding | Author-only immutable manifest; artifact IDs must already be present in the decision evidence references; canonical RFC 8785 payload binds exact decision/finding/revision and artifact digests; manifest must precede signing/approval | `tests/test_decision_evidence.py`, `tests/test_identity.py`, `tests/test_migrations.py`, `tests/test_postgres_persistence.py` | Source identity and claim truth remain unverified; privileged database writers can replace bytes and digest; no external anchor or VEX export |
| Ed25519 decision signatures | Offline operator-bound public-key registration/revocation; RFC 8785 domain-separated envelope v2 binds immutable decision fields and the canonical evidence-manifest digest; v1 remains supported for historical verification | `tests/test_decision_signatures.py`, `tests/test_decision_evidence.py`, `tests/test_migrations.py`, `tests/test_postgres_persistence.py` | Signature is optional; no hardware-backed key custody, independent identity proof or external audit anchoring |
| Independent second-person approval | Separate approval-purpose Ed25519 key and active operator principal; author self-approval rejected; versioned one-author-plus-one-approver policy; approval digest includes the v2 decision envelope and evidence-manifest digest; 30-minute payload window | `tests/test_decision_approvals.py`, `tests/test_decision_evidence.py`, `tests/test_identity.py`, `tests/test_migrations.py`, `tests/test_postgres_persistence.py` | No organizational quorum, anti-collusion guarantee or legal identity proof; source authentication and external anchoring remain absent |
| Source-aware applicability evidence (integrated through PR #55) | Versioned findings persist `osv_reported_affected`, `synthetic_candidate` or `unknown` with source/query provenance; no automated `not_affected` status | `tests/test_applicability.py`, `tests/test_sbom_reassessment.py`, `tests/test_postgres_persistence.py` | OSV result is a provider match, not vendor confirmation; synthetic rule is PEP 440 demo logic; no human-reviewed VEX decision |
| CISA KEV and FIRST EPSS reassessment enrichment (integrated through PR #55) | Optional, separately enabled CVE enrichment; validates CISA catalog envelope and FIRST score/percentile bounds; stores per-finding provider state and source/date provenance in the immutable assessment snapshot | `tests/test_intelligence.py`, `tests/test_sbom_reassessment.py`, `tests/test_postgres_persistence.py` | Disabled by default; capped at 100 CVEs per assessment; provider failures are `unavailable`/`incomplete`; KEV/EPSS do not prove component applicability or drive VEX/CRA decisions |
| Posture assessment | Missing data stays unverified; declared exposed management interface is high risk | `tests/test_posture_evidence_boundaries.py` | Uses declared metadata, not active discovery |
| Identity lifecycle audit | Offline principal/credential creation, issuance, revocation and disablement append audit events in the same transaction; managed API actors use stable principal UUIDs | `tests/test_identity.py`, `tests/test_postgres_persistence.py` | Offline administrator actor is not a human identity; no credential-management HTTP API |
| Audit | SHA-256 hash chain, transaction-scoped writer lock and verification endpoint | `tests/test_audit_chain_boundaries.py`, `tests/test_postgres_persistence.py` | No external checkpoint or immutable store; privileged DB writers remain in the trust boundary |
| Console | Same-origin assets, CSP and baseline response headers | `tests/test_operator_console.py` | No real-browser security suite |

## Evidence handling

- Allowed sources are `manual`, `router_import`, `network_observation`, `sbom`, `firmware` and `vendor_api`.
- Source observation time and server recording time are stored separately.
- Confidence is descriptive metadata, not a probability or verification state.
- The server assigns `unverified`.
- Observations may remain unassigned.
- References are opaque; the API does not fetch them.
- A client-supplied observation hash remains untrusted metadata; it is distinct from the server-computed artifact digest.
- Actual artifact bytes are stored in a bounded database BLOB and linked to one observation.
- Upload computes SHA-256 over received bytes; verify/download recomputes digest and byte length.
- Artifact uploads are limited to 5 MiB, use an allow-list of declared media types and are downloaded as an attachment with `nosniff`.
- Audit payloads contain artifact ID, digest, byte length and media type, never raw bytes or observation values.
- Artifact integrity does not authenticate the source, prove claim truth, detect malware or protect against a privileged database writer that can replace both bytes and digest.
- Artifact references are not yet bound to a specific vulnerability decision revision.

Evidence observations are not yet used for device matching, conflict resolution or posture calculations.

## Posture and internet exposure

The posture service evaluates declared security-profile fields. Unknown values remain unknown. An internet-exposed device or management interface is reported as high risk, but the application does not independently test reachability.

## SBOM boundary

CycloneDX parsing is a bounded subset. Components without PURLs are retained but cannot be matched by the local demo feed. Synthetic `DT-DEMO-*` advisories support deterministic demonstrations only. Product-scoped OSV enrichment is optional and bounded per import: at most 50 unique exact PURL/version queries and one absolute, cancellable 10-second wall-clock deadline covering query preparation and awaited OSV I/O; cancellation is cooperative and cannot pre-empt synchronous CPU work. Duplicate occurrences share one query and findings map back to each occurrence. Import metadata records source, check time, query counts and `complete`/`incomplete`/`disabled` status. Failures, malformed responses, exhausted budgets and components without PURLs produce incomplete coverage; no result must not be interpreted as proof that a component is vulnerability-free.

## Lifecycle data

The current persistence model stores `support_until` on a device. It does not yet implement a full lifecycle model with independent support status, end-of-life announcement and source provenance. Do not describe those fields as implemented.

## Audit guarantees

The hash chain can detect modification of retained entries and gaps when a later retained entry references a missing predecessor. It cannot detect deletion of the final entry or suffix without an independently retained checkpoint. A privileged attacker able to rewrite the database can recompute the chain. Application writers sharing one database are serialized by a singleton state-row update held for the domain/audit transaction; SQLite acquires `BEGIN IMMEDIATE` with a 10-second busy timeout, while PostgreSQL holds a row lock with a 10-second transaction-local lock timeout. This does not coordinate external writers that bypass the application or provide an independent checkpoint.

## Before production use

Complete the managed-identity rollout, retire legacy shared-key mode before multi-user deployment, add human identity/MFA only if required, implement rate limiting, reviewed migration and rollback procedures, independent audit anchoring, retention policy, lock-contention monitoring, operational monitoring and a documented deployment model. See [Threat model](threat-model.md) and [Release readiness](release-readiness.md).

## Repository and CI security gates

The repository workflow applies separate controls to the development and delivery toolchain:

- pip-audit -r requirements.txt audits the runtime dependency set.
- pip-audit -r requirements-dev.txt audits the development dependency set, including runtime requirements inherited through -r requirements.txt.
- pre-commit validate-config validates the hook configuration; pre-commit install-hooks provisions the configured hook environments in CI. This does not mean CI executes every hook on all files.
- Gitleaks v8.30.1 scans Git history reachable from the checked-out refs. CI uses actions/checkout with fetch-depth: 0, passes --all --full-history to Git, verifies the official Linux x64 release archive SHA-256 (551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb) before execution, and uses full redaction. The artifact is downloaded from the Gitleaks v8.30.1 GitHub release. `.gitleaksignore` contains one exact fingerprint exception for a confirmed synthetic Idempotency-Key test fixture falsely classified by the generic-api-key rule; the fixture has been shortened to avoid new matches. The CI failure diagnostic prints only the rule, file, commit, line and fingerprint, never the secret value.
- The CI workflow has read-only contents permissions and bounded job timeouts. CodeQL uses its separate workflow permissions.

These gates improve visibility into known dependency advisories and detected secret patterns. They do not establish complete secret detection, complete supply-chain assurance, or production security. A clean scan is not a substitute for manual review of private data, history and findings.

### Temporary ggshield upstream pin

The current development requirements and pre-commit hook pin GitGuardian ggshield to upstream commit e7dc8bcc117079882e6521d16b1016419878af9e. The latest official release observed during this review is v1.56.1, whose dependency metadata constrains oauthlib below 4; that selects a vulnerable pre-4.x version in the affected environment. The [pinned upstream merge commit](https://github.com/GitGuardian/ggshield/commit/e7dc8bcc117079882e6521d16b1016419878af9e) is GitHub-signature verified (API verification reason: valid), is reachable from the official GitGuardian main history, and includes the dependency update to oauthlib 4.0.1. Its pyproject.toml permits oauthlib>=3.2.1,<5, and its lock file records 4.0.1.

This is a temporary source commit pin, not an official ggshield release. Replace both pins with an appropriate official release as soon as GitGuardian publishes one with the patched dependency constraint. Keep the runtime and development dependency audits enabled; do not suppress the finding.
