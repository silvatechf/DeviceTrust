# Roadmap

This roadmap distinguishes implemented prototype behavior from work that remains planned. A checked item means code exists; it does not by itself mean production readiness or release validation.

## Milestone 0 — Repository bootstrap
- [x] Import prototype without rewriting working behavior.
- [x] Establish architecture, threat model and honest product boundaries.
- [x] Integrate changes through pull requests.

## Milestone 1 — Exposure, lifecycle and evidence foundation
- [x] Add nullable, provenance-backed internet exposure.
- [x] Model management interfaces separately from generic open ports.
- [x] Add lifecycle state for product/model and firmware.
- [x] Add bounded evidence observations with source, timestamps, confidence and verification state.
- [x] Support unassigned observations for unidentified assets.
- [x] Ensure unknown is never treated as safe.
- [x] Add deterministic findings and tests.

## Milestone 2 — Evidence normalization and vulnerability intelligence
### Evidence normalization and identity
- [x] Define canonical attribute vocabulary, normalization boundaries and source provenance.
- [x] Specify conflict retention, temporal semantics and reviewed association safeguards.
- [x] Implement deterministic pure normalizers with raw-value preservation and version metadata.
- [x] Add a bounded, read-only normalized projection for selected attributes, with tests for unknown and invalid values.
- [ ] Expand normalizer coverage for stale and conflicting observations and additional source adapters.
- [ ] Implement reviewed association only after actor identity and authorization limitations are addressed.
- [ ] Define explicit per-control evidence acceptance and freshness rules before posture integration.

### Vulnerability intelligence
- [x] Implement bounded CycloneDX subset parsing and PURL-based component matching.
- [x] Add optional best-effort OSV lookup scoped to component identity and version.
- [ ] Strengthen CycloneDX validation against the supported schema version.
- [ ] Evaluate affected version ranges and ecosystem identifiers.
- [ ] Add CISA KEV enrichment and preserve source/timestamp.
- [ ] Treat runtimes and interpreters as SBOM components.
- [ ] Treat unavailable feeds as incomplete/unknown, not clean.

## Milestone 3 — Security events
- [ ] Define authenticated event schema and source identity.
- [ ] Detect out-of-window maintenance actions, unexpected setpoint changes and new management origins.
- [ ] Build a simulated refrigeration incident scenario.
- [ ] Add replay resistance and event provenance.
- [ ] No physical control commands in the MVP.

## Milestone 4 — Operational readiness
- [ ] Per-client identities, RBAC and secret rotation.
- [ ] Alembic migrations and PostgreSQL tests.
- [ ] External audit anchoring.
- [ ] Operator exposure/lifecycle report.
- [ ] CI hardening, dependency and container scanning.
- [ ] Rate limiting, operational alerting, backup/restore and deployment rollback evidence.

## Release and portfolio gates
- [ ] Review full Git history and confirm no secrets or unintended private material.
- [ ] Resolve repository signature policy and confirm verified commits where required.
- [ ] Select and publish an explicit license decision.
- [ ] Validate a clean checkout and disposable database on the exact release candidate.
- [ ] Capture genuine screenshots from the running application.
- [ ] Confirm required CI and CodeQL checks on the exact candidate commit.
- [ ] Set repository description and topics after confirming the final public positioning.
- [ ] Publish a versioned release only after the release-readiness gates are satisfied.