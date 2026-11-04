# Evidence Ingestion

## Scope

The first evidence-ingestion increment stores bounded observations without changing the existing device security profile or posture calculations. It accepts observations associated with a known device or unassigned observations for assets that have not yet been identified.

## API

- `POST /evidence`: record one observation.
- `GET /evidence`: list observations, optionally filtered by `device_id`.
- `GET /evidence/normalized`: return a read-only normalized projection with canonical attribute, normalized value, normalizer version and any normalization error. The original observation remains unchanged.

All endpoints require the existing shared API key. This is a prototype operator boundary, not per-user authorization.

Supported source types: `manual`, `router_import`, `network_observation`, `sbom`, `firmware`, and `vendor_api`.

Each observation stores its attribute and bounded string value, source type, source observation time, server recording time, confidence, optional evidence reference and optional SHA-256 artifact hash. The server always sets `verification_status=unverified`; clients cannot mark their own observations verified.

Unassigned observations use `device_id=null`. The system does not infer identity or merge observations into a device automatically. Association and conflict resolution are later workflow capabilities. The normalized projection is deterministic and side-effect-free; unknown attributes remain unclassified, invalid known values retain their raw value and expose an error, and normalization does not alter verification status or posture.

## Security boundaries

- Unknown source types and unexpected fields are rejected.
- Attribute names, values, references and hashes have explicit length/format limits.
- `observed_at` must include a timezone; accepted timestamps are normalized to UTC.
- `GET /evidence` uses stable ordering and bounded pagination (`limit` 1–200, default 100; `offset` 0 or greater).
- Evidence references are opaque identifiers, not fetched URLs; the API does not dereference them.
- The hash records a supplied artifact digest; it does not prove the artifact's origin or authenticity.
- The audit event records observation metadata and digest, not the potentially sensitive raw value.
- The current shared API key still grants broad access to all observations.

## Persistence

The feature adds an `evidence_observations` table. Existing `devices`, vulnerability and audit tables are unchanged. SQLAlchemy `create_all` creates the new table on startup for fresh or existing databases; it is not a general schema migration system.
