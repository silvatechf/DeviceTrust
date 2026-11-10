# Evidence Ingestion

## Scope

Evidence ingestion records bounded observations without changing the device security profile or posture calculations. Observations may reference a known device or remain unassigned.

## Observation API

- `POST /evidence`: record one observation.
- `GET /evidence`: list observations, optionally filtered by `device_id`.
- `GET /evidence/normalized`: return a read-only normalized projection. The original observation remains unchanged.

The API supports legacy shared-key authentication and managed credentials with explicit `evidence:read` / `evidence:write` scopes. Legacy mode remains the default prototype configuration.

Each observation stores its source, attribute, bounded value, source observation time, server recording time, confidence and optional opaque reference or client-supplied hash. The server always assigns `verification_status=unverified`; clients cannot self-verify observations.

## Artifact API

Actual evidence bytes can be attached to an existing observation:

- `POST /evidence/{observation_id}/artifacts`: upload raw bytes.
- `GET /evidence/{observation_id}/artifacts`: list attached artifact metadata.
- `GET /evidence/artifacts/{artifact_id}`: retrieve the artifact manifest metadata.
- `GET /evidence/artifacts/{artifact_id}/verify`: recompute and compare the stored SHA-256 digest and byte length.
- `GET /evidence/artifacts/{artifact_id}/content`: download bytes only after integrity verification succeeds.

Uploads are limited to 1–5 MiB and the declared media type must be one of `application/octet-stream`, `application/json`, `application/pdf` or `text/plain`. The server computes SHA-256 over the exact received bytes; clients cannot supply the artifact digest. An identical observation/digest/media-type upload is idempotent. Artifact metadata, bytes and the audit event are committed in one database transaction.

The artifact record contains a UUID, observation ID, server-computed SHA-256, byte length, declared media type, uploader actor and server recording time. The audit payload records identifiers and digests, never raw artifact bytes. Download responses use `application/octet-stream`, attachment disposition and `nosniff`; untrusted evidence is not rendered inline.

## Security and trust boundaries

- Unknown source types, unexpected fields, malformed hashes and naive timestamps are rejected.
- Observation references remain opaque; the API never dereferences arbitrary URLs.
- Artifact bytes are stored in the application database, not in a filesystem path derived from user input.
- The server recomputes the digest when verifying or downloading. A mismatch is reported; downloads fail closed.
- A duplicate upload returns the existing artifact record without adding a second audit event.
- Artifact upload and its audit event share one transaction.
- Declared media type is metadata, not content sniffing or malware analysis.
- SHA-256 proves byte consistency with the stored digest, not origin, authenticity, safety or claim truth.
- Artifact records are append-only through the exposed API; privileged database operators can still modify or delete both bytes and metadata.
- Evidence artifacts are linked to observations. A separate immutable decision evidence manifest can bind selected artifact IDs already present in a decision's original evidence references to that exact decision/finding/revision. The manifest digest is included in signature and approval envelope v2. The manifest must be created before signing/approval; it cannot be replaced afterward.
- The legacy observation `evidence_hash` field is client-supplied metadata and is not treated as the server-computed artifact digest.

## Persistence

Alembic migration `0013_evidence_artifacts` creates the `evidence_artifacts` table with a bounded-size check and observation/digest/media-type uniqueness. The prototype stores up to 5 MiB per artifact as a database BLOB; this is deliberately bounded but is not a scalable object-storage architecture. SQLite migration and PostgreSQL BLOB persistence coverage passed in CI on PR #64 head `b7728ab`; integration remains pending review.
