# Security Controls and Evidence Model

## Evidence states

- `compliant`: supplied evidence meets the modeled criterion.
- `partial`: evidence demonstrates incomplete implementation.
- `non_compliant`: evidence demonstrates a control failure.
- `unverified`: evidence is absent or insufficient.

A control must never become compliant solely because a field was omitted. The API currently stores declared evidence; it does not independently attest that device statements are true.

## Implemented controls and verification

| Control | Implementation | Verification | Limitation |
|---|---|---|---|
| API authentication | Shared API key, constant-time comparison; missing server key fails closed | `tests/test_api.py` | No per-user identity, scopes, tenant isolation, RBAC or rotation workflow |
| Device input validation | Pydantic models, strict extra-field rejection, bounded identifiers and metadata | `tests/test_api.py` | No rate limiting or request-wide API gateway quotas |
| Evidence ingestion | Authenticated endpoints, source allowlist, bounded fields, opaque references, SHA-256 format validation | `tests/test_api.py` | Shared key is broad; no source-specific identity or rate limiting |
| Evidence verification boundary | Server assigns `unverified`; clients cannot set verification state | `tests/test_api.py` | No independent source attestation or review workflow |
| SBOM request boundary | Streaming 2 MiB body cap; malformed UTF-8/JSON and non-object JSON rejected | `tests/test_sbom_input_limits.py` | Full CycloneDX JSON Schema validation is not implemented |
| SBOM component validation | Bounded component count and field lengths; component object/name/version and PURL validation | `tests/test_sbom_validation.py` | Does not validate every CycloneDX property or dependency graph |
| Local advisory matching | Exact PURL package type/name plus version-before-fixed comparison | `tests/test_sbom_validation.py` | Local records are synthetic demonstration advisories, not vulnerability intelligence |
| OSV lookup | Optional request scoped to package URL and exact component version | `app/sbom.py` | Best-effort external lookup; network/response errors are skipped; no provenance cache or full affected-range persistence |
| Management exposure | Device and management interfaces assessed independently; unknown remains unverified | `tests/test_api.py` | Exposure is declared metadata, not active reachability evidence |
| Configuration posture | Default credentials and insecure interfaces are evaluated independently; missing evidence remains unverified | `tests/test_posture_evidence_boundaries.py` | Interface inventory is declared metadata, not an independent device scan |
| Audit integrity | SHA-256 hash chain with verification endpoint | `tests/test_api.py`, `tests/test_audit_chain_boundaries.py` | No protection against privileged rewrite/recomputation or deletion of the final entries without external checkpoint |
| Vulnerability triage | Enumerated statuses and mandatory justification | `tests/test_api.py` | No approval workflow or separation of duties |

## Evidence ingestion

The first evidence API increment stores observations separately from the existing device security profile:

- Sources are allowlisted: manual, router import, network observation, SBOM, firmware and vendor API.
- Each observation records source observation time and server recording time.
- Confidence is descriptive metadata, not a probability or verification state.
- The server always assigns `unverified`; clients cannot mark their own evidence verified.
- Observations may remain unassigned when the asset is not yet identified.
- References are opaque and are never dereferenced by the API.
- An optional SHA-256 digest checks consistency only when the referenced artifact is independently available; it does not prove authenticity.
- Evidence audit events omit raw values to reduce unnecessary disclosure.

The observation store is not yet consumed by posture assessment, device matching or conflict resolution.

## Internet exposure

Internet exposure is modeled separately from ordinary open interfaces:

- `internet_exposed`: nullable boolean; `null` means unknown.
- `management_interfaces`: declared management plane, protocol, internet exposure and authentication requirement.

An internet-exposed management interface is a high-risk finding even when authentication is required. Authentication does not remove the attack surface. The prototype accepts declared evidence; it does not independently discover public reachability.

## SBOM and vulnerability matching boundaries

- CycloneDX JSON ingestion is a bounded subset, not full schema validation.
- Component identity uses PURL package type/name where available; components without PURLs are retained but not matched by the local demo feed.
- The local advisory file uses synthetic `DT-DEMO-*` records and is for deterministic tests only.
- OSV requests include the component PURL and version. External errors are skipped; absence of a returned finding must not be interpreted as proof that a component is vulnerability-free.
- Ecosystem-specific version semantics, aliases, ranges, qualifiers and provenance need broader integration tests before production use.

## Lifecycle

Track product/model and firmware lifecycle independently:
- `support_status`: supported, end_of_life, unknown.
- `support_until`: vendor-published date, when known.
- `eol_announced_at`: vendor announcement date.
- `lifecycle_source`: vendor advisory or verified source.

Do not infer EOL from missing support metadata.

## Audit guarantees and non-guarantees

The current hash chain detects modification of stored entries when the chain is not recomputed. It detects deletion or reordering when a later retained entry references the missing predecessor. It **cannot detect deletion of the final entry or final suffix** without an independently retained checkpoint. It is not immutable storage and cannot stop a privileged attacker from rewriting the database and chain.

Stronger assurance requires externally signed checkpoints, independently controlled storage or WORM retention. Concurrent writers also need a serialized chain-head mechanism before multi-worker production deployment.
