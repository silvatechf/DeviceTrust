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
| Unauthorized API access | Legacy shared key or managed principal-bound credentials with expiry, revocation and explicit route scopes | API and identity tests cover authentication and scope boundaries; legacy mode remains default and there is no tenant isolation |
| Device identifier injection | Strict Pydantic pattern and extra-field rejection | API tests cover traversal-like identifiers and unknown fields |
| Malformed or oversized SBOM | 2 MiB streaming body cap; component count and field limits; JSON/PURL validation | Input-limit and SBOM validation tests; full CycloneDX schema validation remains absent |
| Incorrect CVE matching | PURL type/name matching for local demo records; version-specific OSV query | Tests cover ecosystem/package mismatch and fixed versions; local feed is synthetic |
| False compliance from missing data | `unverified` state | Posture tests cover unknown exposure and management interfaces |
| Internet-exposed management | Separate management-plane posture assessment | API test covers exposed admin interface even when authentication is required; exposure is declared metadata |
| Concurrent audit writers | Singleton state-row lock; SQLite IMMEDIATE transaction and PostgreSQL row lock | Concurrent application writers cannot append from the same head; lock-row update and audit append share the domain transaction |
| Audit database rewriting | SHA-256 hash chain | Tests detect mutation; final-entry deletion and privileged recomputation are not detectable without external checkpoints |
| Compromised API key | Individually revocable managed credentials and explicit scopes | Legacy mode remains available; no tenant isolation or MFA |
| Forged or altered review decision | Ed25519 detached signature over a versioned canonical decision envelope; signature re-verification on read | Key possession is not legal identity; author signatures remain optional |
| Self-approved or collusive review | Separate approval-purpose Ed25519 key, distinct active operator principal, versioned one-author-plus-one-approver policy and exact decision-digest binding | Integrated in main through PR #62; no organizational quorum, legal identity proof or anti-collusion guarantee |
| Signing-key compromise | Operator-held private keys; public-key registration, expiry and revocation | No hardware-backed key custody, automated compromise response or independent identity proof |
| Resource exhaustion | SBOM body and component limits | No global request rate limit, concurrency quota or reverse-proxy policy |
| Evidence artifact substitution or database corruption | Server-computed SHA-256 and byte length; digest rechecked before download; artifact and audit event share a transaction | Tests cover altered BLOB detection and fail-closed download; a privileged database writer can replace both bytes and stored digest without an independent checkpoint |
| Evidence upload abuse | 5 MiB streaming cap, allow-listed declared media types, observation-scoped attachment and opaque attachment downloads | Tests cover oversized/empty/unsupported uploads and read/write scopes; no malware scanning, content sniffing or rate limit |

## Abuse cases to test

1. Call protected routes without a key, with a wrong key, and when the server key is unset.
2. Submit traversal-like device IDs, unexpected fields, malformed JSON and oversized SBOM bodies.
3. Submit non-object SBOM components, invalid PURLs, PURL/version mismatches and package-name collisions across ecosystems.
4. Verify that unknown exposure remains unverified and an exposed management interface is high risk.
5. Mutate retained audit entries and document the final-suffix deletion limitation.
6. Attempt self-approval using a second credential and a second key bound to the author principal.
7. Attempt approval without a trusted author signature, with a decision-signing-purpose key, with an expired payload, or after a newer decision revision exists.
8. Disable or revoke an approver after approval and verify that historical signature validity remains distinct from current trust and policy eligibility.
9. Upload empty, oversized and unsupported-media artifacts; verify the server rejects them before persistence.
10. Modify stored artifact bytes without changing the digest; verify integrity detection and fail-closed download.
11. Verify an evidence:read-only credential cannot upload artifacts and that artifact metadata/content requires evidence:read.
12. Inject an audit append failure during artifact attachment and verify both artifact and audit writes roll back.

## Residual risk

Decision signatures and independent second-person approval are integrated in main, but signatures are not mandatory for every decision and the prototype cannot prove organizational independence, prevent collusion or establish legal identity. Evidence artifacts are now stored as bounded database BLOBs with server-computed SHA-256 digests and byte-length checks; verification detects changes to retained bytes and downloads fail closed on mismatch. This does not authenticate the source, validate the claim, scan for malware or bind an artifact to a specific vulnerability-decision revision. A privileged database operator can still replace both the artifact bytes and its stored digest, or alter/delete the audit chain, because no independent checkpoint or external trust anchor exists. Revoked keys remain mathematically verifiable for historical signatures, while their current trust status is reported as revoked.



The prototype is a single trust domain. Any valid API key can read and modify all inventory and triage records. Do not expose it as a multi-customer service or use it as the sole source of security decisions.

## Safety boundary

A DeviceTrust alert does not stop an attacker from changing a physical device. Prevention and safe operation must be enforced by manufacturers, secure configuration, network segmentation, independent safety controls and engineered operational procedures.
