# Release Readiness

## Current status

**Public development repository; no versioned release; not production-ready.**

The project can be presented as an engineering prototype if its boundaries are stated clearly. It must not be described as a production security platform, active device scanner, CRA conformity assessment or protective control.

## Before publishing a versioned release

- [x] README describes the implemented scope and major non-goals.
- [x] Architecture, threat model, security controls and prototype limitations are documented.
- [x] Security reporting and contribution guidance exist.
- [x] A local synthetic-data demo runbook exists.
- [ ] Select and add an explicit license, or formally decide to retain all rights.
- [ ] Manually review the complete Git history for private/customer data and unintended files; review and triage Gitleaks findings without treating a clean scan as proof of complete secret detection.
- [ ] Verify branch protection/rulesets and required checks on the default branch; repository merge-method settings currently allow merge commits, rebase and squash, so use squash for focused feature PRs unless preserving a merge commit is technically justified.
- [ ] Define any prospective commit-signature policy in repository settings.
- [ ] Run the candidate from a clean checkout with a disposable database.
- [x] Add Alembic baseline migration and PostgreSQL migration/persistence CI coverage.
- [ ] Verify PostgreSQL startup, persistence and restart behavior in a clean local Compose deployment.
- [ ] Verify console flows and API error paths in a real browser at desktop/mobile sizes.
- [x] Test concurrent complete API/domain writes and transaction failure behavior on SQLite and PostgreSQL.
- [x] Verify Alembic upgrade/downgrade paths on disposable SQLite and PostgreSQL databases in CI, including decision-signature and approval schema revisions.
- [x] Verify evidence-artifact migration upgrade/downgrade and PostgreSQL BLOB persistence on PR #64 head `b7728ab` (CI passed).
- [x] Cover product-release SBOM comparison semantics (PURL identity boundaries, ambiguity, unidentified components, release isolation, authentication and read-only behavior) in automated tests; exact PR-head CI and CodeQL evidence is recorded in [PR #33](https://github.com/silvatechf/DeviceTrust/pull/33).
- [ ] Demonstrate backup/restore and rollback.
- [ ] Inspect exact-candidate CI results (pre-commit configuration, runtime and development dependency audits, Ruff, Bandit, tests, PostgreSQL and Compose), CodeQL and Gitleaks; record their URLs and manually triage findings. For the main candidate `27efc34`, post-merge CI and CodeQL Python/JavaScript passed. Keep a fresh check for every later candidate.
- [ ] Capture genuine screenshots from the running app using synthetic data only.
- [ ] Complete the documentation and residual-risk review.

A checkbox must be marked only when the check has actually been performed and evidence is available.

## Demo acceptance

- Install dependencies using the documented development requirements.
- Run pre-commit configuration validation, Ruff, Bandit, pip-audit -r requirements.txt, pip-audit -r requirements-dev.txt, Node syntax validation and pytest.
- Start the app with a disposable SQLite database and local API key.
- Seed synthetic data and follow [the demo runbook](demo-runbook.md).
- Verify inventory, posture, SBOM import, justified triage, report download and audit verification.
- Verify product-release SBOM import, listing and read-only comparison of two accepted imports for the same release, using the [comparison walkthrough](demo-runbook.md).
- Confirm the console key is not persisted in browser storage.
- Confirm malformed and oversized SBOM requests are rejected.
- Confirm no local database, credentials, environment files or generated artifacts are committed.

## Production blockers

- Managed API authentication provides principal-bound credentials, expiry, revocation and route scopes; legacy shared-key mode remains the default. There is no human login, MFA/SSO, tenant isolation or customer-facing role hierarchy.
- The browser console receives the configured API token in page memory; there are no server-side browser sessions or backend-for-frontend.
- Credential and signing-key administration remains offline CLI only.
- Alembic migrations and explicit upgrade/downgrade paths are implemented; future schema changes still require reviewed migration scripts and coordinated rollback procedures.
- Ed25519 decision signatures and independent second-person approval are integrated in main through PRs #58 and #62. They establish key control and a technical two-person workflow, not legal identity or organizational independence.
- Audit-chain appends are serialized for application writers sharing one database, but there is no external checkpoint or immutable retention; a privileged database administrator can still rewrite the chain.
- The audit-chain state migration is additive. Its downgrade removes the required lock row; the new application then fails closed on writes until the migration is reapplied or the previous application version is restored. Automated downgrade tests use isolated disposable databases only; production rollback still requires coordinated application/database rollback and a preserved backup.
- CycloneDX support is a bounded subset.
- Local advisories are synthetic; optional OSV lookup is best-effort.
- Evidence normalization covers selected attributes only; observations are not associated automatically or consumed by posture. Observation-linked artifact BLOBs and server-computed digest checks are under validation; source authentication, malware scanning and exact decision-revision binding are not implemented.
- No global rate limiting, concurrency quota or operational alerting.
- PostgreSQL migration/persistence is covered by CI; backup/restore, rollback and production TLS have not been demonstrated.

## Claims supported by the current implementation

- Built a Python/FastAPI modular-monolith prototype for IoT inventory and declared security-posture assessment.
- Implemented bounded evidence ingestion and a read-only normalized projection for selected attributes.
- Implemented bounded observation-linked artifact storage with server-computed SHA-256, byte-length verification, fail-closed downloads and transactional audit metadata (pending CI/review/integration in the current branch).
- Implemented bounded CycloneDX JSON parsing and PURL-based matching against synthetic demo advisories, with optional best-effort OSV lookup.
- Implemented authenticated product-release SBOM persistence for a bounded CycloneDX JSON 1.5 subset, including import provenance metadata, component occurrences, digest-based idempotency and component-scoped synthetic findings.
- Implemented justified vulnerability triage, JSON/Markdown reports and SHA-256 audit-chain verification.
- Implemented managed API identity and explicit route-scope enforcement, plus offline Ed25519 public-key lifecycle and detached decision-signature verification.
- Implemented independent second-person approval using a distinct active operator principal, an approval-purpose Ed25519 key and a versioned policy.
- Integrated linting, static security checks, dependency auditing, JavaScript syntax validation and pytest into CI.
- Documented trust boundaries, threat scenarios, engineering decisions and residual risks.

Avoid claims of complete CVE coverage, independent device attestation, immutable audit storage, multi-tenant security, attack prevention or CRA certification.
