# Changelog

All notable changes to DeviceTrust will be documented here.

The project has not published a versioned release yet. This file records the current development scope; it is not a release announcement.

## Unreleased

### Added
- FastAPI device inventory and evidence-oriented posture prototype.
- Bounded CycloneDX JSON ingestion with PURL-scoped synthetic demonstration advisories and optional best-effort OSV lookup.
- Product-scoped persistence for accepted CycloneDX JSON 1.5 SBOM imports, component occurrences and component-scoped synthetic findings; duplicate imports are idempotent per product release, format and content digest.
- Vulnerability triage with mandatory justification.
- JSON and Markdown device reports.
- SHA-256 hash-chained audit records and integrity verification, with documented limitations.
- Authenticated evidence observation ingestion, unassigned observations and bounded listing.
- Initial read-only normalized evidence projection for selected attributes.
- Same-origin local operator console with inventory, posture, SBOM, triage, reports and audit views.
- CI checks for Ruff, Bandit, dependency auditing, JavaScript syntax and pytest.
- Threat model, architecture, evidence, security-control and release-readiness documentation.
- Engineering decision records for architecture, authentication boundaries, evidence normalization, SBOM scope, audit integrity and the operator console.
- Security test matrix linking implemented controls to automated test locations and outstanding manual verification.
- Synthetic food-processing and cold-chain demo records, sample CycloneDX document and repeatable local runbook.

### Changed
- Repositioned the product hypothesis around Product Security Intelligence & Evidence Management for connected and embedded product manufacturers.
- Clarified product-security consultancies and specialist integrators as complementary users and potential channels.
- Kept food production and cold-chain as a synthetic demonstration context rather than the product's market boundary.
- Reordered the roadmap around operational foundations, persistent product/SBOM data, reviewed vulnerability decisions and developer workflows.
- Updated the interview guide to distinguish the current prototype from the proposed product direction and CRA boundaries.

### Security and limitations
- The application remains a local/single-trust-domain prototype.
- Shared API-key authentication is not individual identity, RBAC or tenant isolation.
- The audit chain is tamper-evident, not immutable.
- Local advisories are synthetic; optional OSV lookup is not comprehensive vulnerability coverage.
- Evidence observations are not independently attested, automatically associated or consumed by posture assessment.
- Demo device identities, vendor, package identifiers and advisory findings are fabricated and are not real supplier data or confirmed vulnerabilities.
- No active discovery, real-time monitoring, intrusion prevention, physical equipment control, CRA conformity assessment or production-readiness claim is made.
