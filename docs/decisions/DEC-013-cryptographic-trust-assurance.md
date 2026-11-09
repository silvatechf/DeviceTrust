# DEC-013: Cryptographic trust, independent approval and audit anchoring

- Status: Partially implemented in PR #57; Ed25519 key registry and detached decision-signature verification implemented, approval/evidence/anchoring pending
- Date: 2026-11-09
- Scope: Attributable vulnerability decisions, evidence provenance and audit integrity

## Context

DeviceTrust currently records append-only vulnerability decision revisions and links each revision to a managed operator principal. Decision creation and its application audit event share one database transaction. The audit log is a SHA-256 hash chain with serialized application writers.

These controls provide application-level traceability, but they do not establish cryptographic authorship, independent approval, truth of referenced evidence or tamper resistance against a privileged database operator. The application database and its audit chain share one trust boundary.

The prototype must close these gaps without storing operator private keys, turning an API token into a digital signature, or claiming legal identity and manufacturer authority from a technical principal.

## Decision

Implement trust assurance as four separate, composable controls. They must not be conflated into one generic "verified" flag.

### 1. Detached Ed25519 signatures for review decisions

- Use Ed25519 detached signatures over a versioned, domain-separated signing envelope. Canonicalize the envelope with RFC 8785 JSON Canonicalization Scheme (JCS), UTF-8 bytes and the fixed binary domain prefix `DeviceTrust` + NUL + `DecisionSignature` + NUL + `v1` + NUL.
- The envelope binds at minimum: schema/version identifier, decision ID, exact assessment finding ID, revision, predecessor decision ID, principal ID, decision state, justification, responses, evidence manifest digest and creation timestamp.
- Canonicalization uses RFC 8785 JCS and is tested for deterministic output. Do not sign arbitrary API JSON, database serialization, or a representation that can change between runtimes.
- The server exposes the exact canonical signing bytes to the decision author, verifies submitted signatures using registered public keys and persists the signature, key ID/fingerprint, algorithm, signing-envelope version and envelope digest.
- Private keys are generated and retained by the operator or their approved key-management system. DeviceTrust must never store private keys or expose a server-side signing endpoint.
- Public keys are registered to an active managed operator principal through an offline administrative workflow. Key rotation, expiry, revocation and historical verification must be explicit.
- A managed API token authenticates a request; it is not proof that the holder controls the signing key. Both checks are required.
- A valid signature proves possession of a registered private key over the signed bytes. It does not by itself prove a person's civil identity, employment, authority to represent a manufacturer or correctness of the decision.

### 2. Independent second-person approval

- A decision requiring approval remains pending until a distinct active operator principal approves the exact decision digest.
- The author cannot approve their own decision. The approver must authenticate with a managed principal and provide a valid signature from a separately registered key.
- Approval signs a domain-separated envelope containing the decision digest, approval purpose, approver principal, timestamp and policy version.
- Any new decision revision invalidates approval of the superseded revision for current export purposes; historical signatures and approvals remain immutable and verifiable.
- Approval policy is explicit and versioned. The initial policy is one author signature plus one distinct approver signature; it is not described as organizational quorum or legal sign-off.
- VEX export must require the current revision to meet the configured approval policy. There is no implicit approval and no fallback to the author.

### 3. Evidence integrity and provenance verification

- Keep evidence references opaque and never dereference arbitrary user-supplied URLs from the API.
- Introduce an evidence manifest that binds each evidence item to a SHA-256 digest, media type, byte length, source, observation/recording times and optional signer/key identity.
- Verify uploaded artifact digests against the manifest before acceptance. If evidence is signed, verify the detached signature against a registered, purpose-appropriate public key.
- Preserve separate states for integrity verified, signature verified, source authenticated and claim reviewed. None implies another.
- A digest proves byte equality with the supplied digest, not source identity or factual correctness. A valid signature proves control of a key, not the truth of the signed claim.
- Do not label evidence "verified" without naming the exact verification performed and its trust policy.

### 4. External audit checkpoints

- Periodically produce a deterministic checkpoint containing the audit sequence number, current chain head, previous checkpoint digest, checkpoint timestamp and format version.
- Sign checkpoints with a dedicated anchoring key whose private material is outside the application database and ordinary API runtime.
- Export checkpoints for retention in an independently administered immutable/WORM store or transparency service. The first implementation may provide a signed export and independent verifier; it must not claim an external anchor until an external system has acknowledged durable retention.
- The verifier must detect altered entries, missing interior entries, rollback to an older checkpoint and a truncated suffix when compared with a separately retained later checkpoint.
- Keep checkpoint signing keys separate from operator decision-signing keys. Compromise of one key class must not authorize the other operation.

## Data and API boundaries

- Add versioned signature/key/approval/checkpoint records as append-only entities with explicit foreign keys and uniqueness constraints.
- Persist public keys, fingerprints, algorithms, purposes, activation/revocation timestamps and principal bindings; never persist private key material.
- Keep signature verification deterministic and independent of request ordering.
- Use explicit scopes for key administration, decision signing, approval and checkpoint operations. Unknown routes and missing scopes fail closed.
- Preserve current decision history and audit events. Existing unsigned decisions remain historical records and must not be silently upgraded or treated as signed/approved.
- VEX generation must consume only the latest decision revision and must fail closed when required signatures, approvals, evidence checks or source BOM references are missing.
- Do not export raw evidence URLs, reviewer free text or sensitive evidence by default.

## Rollout sequence

1. **Signature foundation (implemented in PR #57):** canonical domain-separated envelope, Ed25519 verification, operator-bound public-key registry, offline registration/revocation and signature re-verification. The implementation uses `cryptography` and keeps private keys outside DeviceTrust. RFC 8785 canonicalization is used by the implementation; independent cross-language test vectors and a formal key-custody runbook remain follow-up work.
2. **Decision signing (initial implementation in PR #57):** an author can attach one verified detached signature to an immutable decision revision; historical unsigned records remain explicitly unsigned. Making a signature mandatory for every new decision is not yet enforced.
3. **Second-person approval:** separate approver identity and signature; export eligibility bound to the exact current revision and policy.
4. **Evidence verification:** bounded artifact manifest and digest/signature verification with separate trust states.
5. **Audit anchoring:** signed checkpoint format, independent verifier, then one explicitly supported external immutable-storage integration.
6. **VEX export:** only after the signature, approval, evidence and BOM-reference preconditions are enforced and tested.

Each stage is a separate implementation change with migration, threat-model update, tests and documented operational procedure. Do not bundle all stages into one large migration or claim a control is implemented merely because its schema exists.

## Security requirements and acceptance criteria

- Private-key material never appears in API requests, logs, database rows, audit payloads, CI artifacts or repository files.
- Signature verification rejects altered payloads, wrong key purpose, unknown/revoked keys, mismatched principals, unsupported algorithms and unsupported envelope versions.
- Canonicalization has published test vectors and produces identical bytes across supported runtimes.
- An author cannot approve their own decision, including through a second credential belonging to the same principal.
- Approval is invalid for current export eligibility after a new decision revision is appended.
- Evidence digest mismatch, missing manifest fields and untrusted signing keys fail closed.
- External checkpoint verification detects chain rewrite, truncation and rollback when an independently retained checkpoint is supplied.
- SQLite and PostgreSQL migration, transaction, concurrency and rollback behavior are tested.
- Logs and audit records contain identifiers and digests, not private keys, raw evidence bytes, credentials or unredacted sensitive references.
- Documentation distinguishes key possession, principal attribution, identity proof, source authentication, evidence integrity, claim truth and legal authority.

## Consequences

This design strengthens technical accountability without pretending that cryptography creates organizational authority. It adds key lifecycle and operational responsibilities, and therefore must be delivered incrementally. The application remains a prototype until key custody, recovery, revocation, independent retention, access governance and deployment procedures are demonstrated.

## Explicit non-goals

- Storing private keys in DeviceTrust or signing decisions with a server-held shared key.
- Treating API credentials, GitHub identity or a managed principal as a qualified electronic signature.
- Claiming eIDAS qualified trust services, legal non-repudiation, CRA conformity or manufacturer authority.
- Fetching arbitrary evidence URLs or treating a SHA-256 digest as proof of truth.
- Calling the audit chain immutable before independent checkpoint retention is operational.
