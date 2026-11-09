# Threat Model

## Scope

The prototype manages device metadata, posture evidence, SBOM documents, vulnerability findings and audit events. It does not sit inline with device traffic and does not issue commands to physical controllers.

## Assets

- Device inventory and identifiers.
- Firmware and lifecycle metadata.
- SBOM documents and component versions.
- Vulnerability triage decisions.
- API credentials and authorization context.
- Audit history and evidence provenance.

## Trust boundaries

- External API clients to FastAPI.
- Uploaded SBOM documents to parser and persistence.
- Device-reported metadata to operator-verified evidence.
- Application to external vulnerability intelligence services.
- Application database to backup and audit-storage systems.

## Threats and current evidence

| Threat | Current mitigation | Evidence / limitation |
|---|---|---|
| Unauthorized API access | Shared API key, constant-time comparison, fail-closed configuration | API tests cover missing/invalid credentials; no identity-scoped authorization or tenant isolation |
| Device identifier injection | Strict Pydantic pattern and extra-field rejection | API tests cover traversal-like identifiers and unknown fields |
| Malformed or oversized SBOM | 2 MiB streaming body cap; component count and field limits; JSON/PURL validation | Input-limit and SBOM validation tests; full CycloneDX schema validation remains absent |
| Incorrect CVE matching | PURL type/name matching for local demo records; version-specific OSV query | Tests cover ecosystem/package mismatch and fixed versions; local feed is synthetic |
| False compliance from missing data | `unverified` state | Posture tests cover unknown exposure and management interfaces |
| Internet-exposed management | Separate management-plane posture assessment | API test covers exposed admin interface even when authentication is required; exposure is declared metadata |
| Concurrent audit writers | Singleton state-row lock; SQLite IMMEDIATE transaction and PostgreSQL row lock | Concurrent application writers cannot append from the same head; lock-row update and audit append share the domain transaction |
| Audit database rewriting | SHA-256 hash chain | Tests detect mutation; final-entry deletion and privileged recomputation are not detectable without external checkpoints |
| Compromised API key | Individually revocable managed credentials and explicit scopes | Legacy mode remains available; no tenant isolation or MFA |
| Forged or altered review decision | Ed25519 detached signature over a versioned canonical decision envelope; signature re-verification on read | Key possession is not legal identity; signature is optional in this prototype; no second-person approval yet |
| Signing-key compromise | Operator-held private keys; public-key registration, expiry and revocation | No hardware-backed key custody, automated compromise response or independent identity proof |
| Resource exhaustion | SBOM body and component limits | No global request rate limit, concurrency quota or reverse-proxy policy |

## Abuse cases to test

1. Call protected routes without a key, with a wrong key, and when the server key is unset.
2. Submit traversal-like device IDs, unexpected fields, malformed JSON and oversized SBOM bodies.
3. Submit non-object SBOM components, invalid PURLs, PURL/version mismatches and package-name collisions across ecosystems.
4. Verify that unknown exposure remains unverified and an exposed management interface is high risk.
5. Mutate retained audit entries and document the final-suffix deletion limitation.

## Residual risk

Decision signatures improve integrity and key attribution, but the application does not yet require signatures for every decision, enforce second-person approval, verify evidence artifacts or anchor audit checkpoints outside the database. A privileged database operator can still alter or delete records; signature re-verification detects changes to signed decision content but does not protect the entire database or audit history. Revoked keys remain mathematically verifiable for historical signatures, while their current trust status is reported as revoked.



The prototype is a single trust domain. Any valid API key can read and modify all inventory and triage records. Do not expose it as a multi-customer service or use it as the sole source of security decisions.

## Safety boundary

A DeviceTrust alert does not stop an attacker from changing a physical device. Prevention and safe operation must be enforced by manufacturers, secure configuration, network segmentation, independent safety controls and engineered operational procedures.
