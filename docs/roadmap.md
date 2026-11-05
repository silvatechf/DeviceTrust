# Roadmap

This roadmap separates completed prototype work from capabilities that still need design, implementation and evidence. A planned item is not an implemented feature. Product priorities are informed by the [market-positioning decision](market-positioning.md): food production, processing and cold-chain operations are the initial application context; agriculture is an adjacent expansion area.

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
- [ ] Expand attribute/source coverage relevant to industrial gateways, controllers and environmental sensors.
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

## Milestone 3 — Food production and cold-chain demonstration

- [ ] Replace the generic camera-centric demo narrative with a clearly labelled synthetic food-processing / cold-chain asset scenario.
- [ ] Demonstrate inventory, declared posture, SBOM findings, justified triage, reports and audit history using existing capabilities.
- [ ] Label all synthetic devices, SBOMs and local advisories; do not imply real-world discovery or live threat intelligence.
- [ ] Validate the workflow with OT integrators and food-sector security practitioners.

## Milestone 4 — Asset intelligence and contextual risk

- [ ] Define safe import formats for external asset inventories.
- [ ] Enrich asset records with vendor, model, firmware, support lifecycle and source provenance.
- [ ] Define an explainable prioritisation model combining technical severity, exposure, operational criticality and evidence confidence.
- [ ] Add reviewed evidence-to-asset association and conflict handling with suitable identity and authorisation controls.
- [ ] Expand SBOM ecosystem/version semantics and vulnerability-intelligence provenance.

## Milestone 5 — Security events and monitoring (not implemented)

- [ ] Define authenticated event schema and source identity.
- [ ] Model event provenance and replay protection.
- [ ] Evaluate passive, read-only integrations for asset and vulnerability changes.
- [ ] Add simulated maintenance-window and unexpected-change scenarios.
- [ ] Keep physical control commands and autonomous remediation out of scope.

## Milestone 6 — Operational readiness (not implemented)

- [ ] Individual operator identities, RBAC, scopes and credential lifecycle.
- [ ] Tenant isolation before multi-customer use.
- [ ] Alembic migrations and PostgreSQL integration tests.
- [ ] External audit checkpoints and serialized concurrent writes.
- [ ] Rate limiting, operational monitoring and alerting.
- [ ] Backup/restore and deployment rollback.
- [ ] Container scanning and documented deployment hardening.

See [Release readiness](release-readiness.md) for the evidence required before a public versioned release.
