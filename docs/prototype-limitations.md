# Prototype Limitations

DeviceTrust is an early-stage engineering prototype. The following boundaries must be reflected in portfolio descriptions and technical discussions.

## Identity and access

- One shared API key protects the API; it is not individual identity, RBAC, scoped authorization or tenant isolation.
- There is no key rotation/revocation workflow.
- The console receives the shared key in browser memory. This is not a production session architecture.

## Evidence and posture

- Device security fields are declared metadata, not independently measured or attested facts.
- Evidence observations default to `unverified`.
- Observations may be unassigned; the application does not infer identity or automatically associate them.
- Normalization covers selected attributes only.
- Stale/conflicting evidence is not resolved.
- Evidence observations do not currently feed posture calculations.
- A supplied artifact digest does not prove source authenticity.

## Vulnerability intelligence

- The CycloneDX parser accepts a bounded subset, not the complete schema or dependency graph.
- Local `DT-DEMO-*` advisories are synthetic demonstration data.
- Optional OSV lookup is best-effort and does not guarantee complete coverage.
- Ecosystem-specific affected-version semantics need broader validation.

## Audit and operations

- SHA-256 hash chaining is tamper-evident, not immutable.
- Deletion of the final audit entry/suffix and privileged database rewrite can evade detection without an external checkpoint.
- Concurrent chain-head updates are not serialized for multi-worker production use.
- SQLite is the default; PostgreSQL integration and restart behavior still need testing.
- SQLAlchemy `create_all` is used; no versioned migration workflow exists.
- Rate limiting, operational alerting, backup/restore and rollback are not demonstrated.

## Product boundary

- No active LAN scanning, packet capture or device agents.
- No inline IDS/IPS, attack prevention or physical safety control.
- No CRA conformity assessment or certification.
