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
- [ ] Review the complete Git history for secrets, private/customer data and unintended files.
- [ ] Verify branch protection/rulesets and required checks on the default branch.
- [ ] Define any prospective commit-signature policy in repository settings.
- [ ] Run the candidate from a clean checkout with a disposable database.
- [x] Add Alembic baseline migration and PostgreSQL migration/persistence CI coverage.\n- [ ] Verify PostgreSQL startup, persistence and restart behavior in a clean local Compose deployment.
- [ ] Verify console flows and API error paths in a real browser at desktop/mobile sizes.
- [ ] Test concurrent audit writes and failure behavior.
- [ ] Demonstrate backup/restore and rollback.
- [ ] Inspect CI and CodeQL results for the exact candidate SHA and record their URLs.
- [ ] Capture genuine screenshots from the running app using synthetic data only.
- [ ] Complete the documentation and residual-risk review.

A checkbox must be marked only when the check has actually been performed and evidence is available.

## Demo acceptance

- Install dependencies using the documented development requirements.
- Run Ruff, Bandit, pip-audit, Node syntax validation and pytest.
- Start the app with a disposable SQLite database and local API key.
- Seed synthetic data and follow [the demo runbook](demo-runbook.md).
- Verify inventory, posture, SBOM import, justified triage, report download and audit verification.
- Confirm the console key is not persisted in browser storage.
- Confirm malformed and oversized SBOM requests are rejected.
- Confirm no local database, credentials, environment files or generated artifacts are committed.

## Production blockers

- Shared API key; no individual identity, RBAC, scopes, revocation workflow or tenant isolation.
- Browser console receives the shared key in page memory.
- No server-side browser sessions or backend-for-frontend.
- Alembic baseline and explicit migration workflow are implemented; future schema changes still require reviewed migration scripts.
- Audit chain has no external checkpoint, immutable retention or multi-writer serialization.
- CycloneDX support is a bounded subset.
- Local advisories are synthetic; optional OSV lookup is best-effort.
- Evidence normalization covers selected attributes only; observations are not associated automatically or consumed by posture.
- No global rate limiting, concurrency quota or operational alerting.
- PostgreSQL migration/persistence is covered by CI; backup/restore, rollback and production TLS have not been demonstrated.

## Claims supported by the current implementation

- Built a Python/FastAPI modular-monolith prototype for IoT inventory and declared security-posture assessment.
- Implemented bounded evidence ingestion and a read-only normalized projection for selected attributes.
- Implemented bounded CycloneDX JSON parsing and PURL-based matching against synthetic demo advisories, with optional best-effort OSV lookup.
- Implemented justified vulnerability triage, JSON/Markdown reports and SHA-256 audit-chain verification.
- Integrated linting, static security checks, dependency auditing, JavaScript syntax validation and pytest into CI.
- Documented trust boundaries, threat scenarios, engineering decisions and residual risks.

Avoid claims of complete CVE coverage, independent device attestation, immutable audit storage, multi-tenant security, attack prevention or CRA certification.
