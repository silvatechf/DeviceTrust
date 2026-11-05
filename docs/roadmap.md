# Roadmap

This roadmap separates completed prototype work from capabilities that still need design, implementation and evidence. A planned item is not an implemented feature.

## Milestone 0 — Repository and engineering baseline

- [x] Establish FastAPI application and SQLAlchemy persistence.
- [x] Document architecture, trust boundaries and prototype limitations.
- [x] Add CI quality/security checks and CodeQL configuration.
- [x] Keep changes reviewable through focused branches and pull requests.

## Milestone 1 — Inventory and declared posture

- [x] Store device inventory and declared security attributes.
- [x] Assess selected controls and expose posture findings.
- [x] Preserve unknown states instead of treating missing fields as safe.
- [x] Model declared internet exposure and management interfaces separately.

## Milestone 2 — Evidence and component findings

### Evidence
- [x] Store bounded observations with source, source time and server recording time.
- [x] Support unassigned observations.
- [x] Keep verification state server-controlled and default to `unverified`.
- [x] Add pure normalization for selected attributes and a read-only projection.
- [ ] Expand attribute/source coverage.
- [ ] Define stale/conflicting observation handling.
- [ ] Add reviewed association only after individual identity and authorization exist.
- [ ] Define per-control evidence acceptance and freshness rules before posture integration.

### SBOM and vulnerability findings
- [x] Parse a bounded CycloneDX JSON subset.
- [x] Validate PURLs and apply PURL-scoped synthetic demo matching.
- [x] Add optional best-effort OSV lookup.
- [ ] Expand schema and ecosystem-specific version semantics.
- [ ] Add intelligence provenance, caching and coverage monitoring.
- [ ] Evaluate CISA KEV enrichment without treating feed absence as safety.

## Milestone 3 — Security events (not implemented)

- [ ] Define authenticated event schema and source identity.
- [ ] Model event provenance and replay protection.
- [ ] Add simulated maintenance-window and unexpected-change scenarios.
- [ ] Keep physical control commands out of scope.

## Milestone 4 — Operational readiness (not implemented)

- [ ] Individual operator identities, RBAC, scopes and credential lifecycle.
- [ ] Alembic migrations and PostgreSQL integration tests.
- [ ] External audit checkpoints and serialized concurrent writes.
- [ ] Rate limiting, operational monitoring and alerting.
- [ ] Backup/restore and deployment rollback.
- [ ] Container scanning and documented deployment hardening.

See [Release readiness](release-readiness.md) for the evidence required before a public versioned release.
