# Security Controls

This document describes what the current code does, where to find its tests and what each control does not guarantee.

## Controls and limits

| Area | Current implementation | Test location | Limitation |
|---|---|---|---|
| API authentication | Shared key, constant-time comparison; missing server key fails closed | `tests/test_api.py` | No individual identity, scopes, RBAC, tenant isolation or rotation workflow |
| Input validation | Pydantic schemas, strict extra-field handling and bounded fields | `tests/test_api.py` | No global rate limit or API gateway quota |
| Evidence ingestion | Source allowlist, bounded values, timezone-aware timestamps and digest format checks | `tests/test_api.py` | No source-specific identity or independent attestation |
| Verification boundary | Server assigns `unverified`; client cannot self-verify | `tests/test_api.py` | No operator review workflow |
| SBOM body | Streaming 2 MiB limit; malformed/non-object JSON rejected | `tests/test_sbom_input_limits.py` | Reverse-proxy limits not validated |
| SBOM components | CycloneDX JSON `specVersion` 1.5 allow-list, component count/field bounds and PURL validation | `tests/test_sbom_validation.py` | Only version declaration is gated; not full CycloneDX schema or dependency-graph validation |
| Local advisory matching | PURL package type/name and version-before-fixed comparison | `tests/test_sbom_validation.py` | Synthetic demo records, not a maintained feed |
| OSV lookup | Optional exact PURL/version query | `tests/test_sbom_osv_response.py` | Best-effort; errors are skipped and coverage is not guaranteed |
| Posture assessment | Missing data stays unverified; declared exposed management interface is high risk | `tests/test_posture_evidence_boundaries.py` | Uses declared metadata, not active discovery |
| Audit | SHA-256 hash chain, transaction-scoped writer lock and verification endpoint | `tests/test_audit_chain_boundaries.py`, `tests/test_postgres_persistence.py` | No external checkpoint or immutable store; privileged DB writers remain in the trust boundary |
| Console | Same-origin assets, CSP and baseline response headers | `tests/test_operator_console.py` | No real-browser security suite |

## Evidence handling

- Allowed sources are `manual`, `router_import`, `network_observation`, `sbom`, `firmware` and `vendor_api`.
- Source observation time and server recording time are stored separately.
- Confidence is descriptive metadata, not a probability or verification state.
- The server assigns `unverified`.
- Observations may remain unassigned.
- References are opaque; the API does not fetch them.
- A supplied SHA-256 digest does not prove who created the artifact.
- Audit payloads omit the raw observation value.

Evidence observations are not yet used for device matching, conflict resolution or posture calculations.

## Posture and internet exposure

The posture service evaluates declared security-profile fields. Unknown values remain unknown. An internet-exposed device or management interface is reported as high risk, but the application does not independently test reachability.

## SBOM boundary

CycloneDX parsing is a bounded subset. Components without PURLs are retained but cannot be matched by the local demo feed. Synthetic `DT-DEMO-*` advisories support deterministic demonstrations only. OSV lookup may be unavailable or incomplete; no result must not be interpreted as proof that a component is vulnerability-free.

## Lifecycle data

The current persistence model stores `support_until` on a device. It does not yet implement a full lifecycle model with independent support status, end-of-life announcement and source provenance. Do not describe those fields as implemented.

## Audit guarantees

The hash chain can detect modification of retained entries and gaps when a later retained entry references a missing predecessor. It cannot detect deletion of the final entry or suffix without an independently retained checkpoint. A privileged attacker able to rewrite the database can recompute the chain. Application writers sharing one database are serialized by a singleton state-row update held for the domain/audit transaction; SQLite acquires `BEGIN IMMEDIATE` with a 10-second busy timeout, while PostgreSQL holds a row lock with a 10-second transaction-local lock timeout. This does not coordinate external writers that bypass the application or provide an independent checkpoint.

## Before production use

Add individual identity and authorization, key lifecycle, rate limiting, migration management, independent audit anchoring, retention policy, lock-contention monitoring, operational monitoring and a documented deployment model. See [Threat model](threat-model.md) and [Release readiness](release-readiness.md).

## Repository and CI security gates

The repository workflow applies separate controls to the development and delivery toolchain:

- pip-audit -r requirements.txt audits the runtime dependency set.
- pip-audit -r requirements-dev.txt audits the development dependency set, including runtime requirements inherited through -r requirements.txt.
- pre-commit validate-config validates the hook configuration; pre-commit install-hooks provisions the configured hook environments in CI. This does not mean CI executes every hook on all files.
- Gitleaks v8.30.1 scans Git history reachable from the checked-out refs. CI uses actions/checkout with fetch-depth: 0, passes --all --full-history to Git, verifies the official Linux x64 release archive SHA-256 (551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb) before execution, and uses full redaction. The artifact is downloaded from the Gitleaks v8.30.1 GitHub release. No repository-specific Gitleaks allowlist or ignore file is configured.
- The CI workflow has read-only contents permissions and bounded job timeouts. CodeQL uses its separate workflow permissions.

These gates improve visibility into known dependency advisories and detected secret patterns. They do not establish complete secret detection, complete supply-chain assurance, or production security. A clean scan is not a substitute for manual review of private data, history and findings.

### Temporary ggshield upstream pin

The current development requirements and pre-commit hook pin GitGuardian ggshield to upstream commit e7dc8bcc117079882e6521d16b1016419878af9e. The latest official release observed during this review is v1.56.1, whose dependency metadata constrains oauthlib below 4; that selects a vulnerable pre-4.x version in the affected environment. The [pinned upstream merge commit](https://github.com/GitGuardian/ggshield/commit/e7dc8bcc117079882e6521d16b1016419878af9e) is GitHub-signature verified (API verification reason: valid), is reachable from the official GitGuardian main history, and includes the dependency update to oauthlib 4.0.1. Its pyproject.toml permits oauthlib>=3.2.1,<5, and its lock file records 4.0.1.

This is a temporary source commit pin, not an official ggshield release. Replace both pins with an appropriate official release as soon as GitGuardian publishes one with the patched dependency constraint. Keep the runtime and development dependency audits enabled; do not suppress the finding.
