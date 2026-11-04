# Roadmap

## Milestone 0 — Repository bootstrap
- Import prototype without rewriting working behavior.
- Establish architecture, threat model and honest product boundaries.
- Integrate changes through pull requests.

## Milestone 1 — Exposure, lifecycle and evidence foundation
- Add nullable, provenance-backed internet exposure.
- Model management interfaces separately from generic open ports.
- Add lifecycle state for product/model and firmware.
- Add bounded evidence observations with source, timestamps, confidence and verification state.
- Support unassigned observations for unidentified assets.
- Ensure unknown is never treated as safe.
- Add deterministic findings and tests.

## Milestone 2 — Evidence normalization and vulnerability intelligence

### Evidence normalization and identity
- [x] Define canonical attribute vocabulary, normalization boundaries and source provenance.
- [x] Specify conflict retention, temporal semantics and reviewed association safeguards.
- [x] Implement deterministic pure normalizers with raw-value preservation and version metadata.
- [ ] Add read-only normalized projections and tests for unknown, invalid, stale and conflicting observations.
- [ ] Implement reviewed association only after actor identity and authorization limitations are addressed.
- [ ] Define explicit per-control evidence acceptance and freshness rules before posture integration.

### Vulnerability intelligence
- [ ] Strengthen CycloneDX validation and component normalization.
- [ ] Evaluate affected version ranges and ecosystem identifiers.
- [ ] Add CISA KEV enrichment and preserve source/timestamp.
- [ ] Treat runtimes and interpreters as SBOM components.
- [ ] Treat unavailable feeds as incomplete/unknown, not clean.

## Milestone 3 — Security events
- Define authenticated event schema and source identity.
- Detect out-of-window maintenance actions, unexpected setpoint changes and new management origins.
- Build a simulated refrigeration incident scenario.
- Add replay resistance and event provenance.
- No physical control commands in the MVP.

## Milestone 4 — Operational readiness
- Per-client identities, RBAC and secret rotation.
- Alembic migrations and PostgreSQL tests.
- External audit anchoring.
- Operator exposure/lifecycle report.
- CI hardening, dependency and container scanning.
