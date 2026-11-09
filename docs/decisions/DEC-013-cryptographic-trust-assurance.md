# DEC-013: Cryptographic trust, independent approval and audit anchoring

- Status: Decision signatures and independent approval integrated through PRs #58 and #62; bounded observation-linked artifact storage and digest verification implemented in PR #64 (CI validated; review/integration pending); exact decision-revision evidence binding, source authentication and external anchoring remain pending
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
- The current v1 envelope binds: schema/version identifier, decision ID, exact assessment finding ID, revision, predecessor decision ID, principal ID, decision state, justification, reviewer detail, evidence references, responses and creation timestamp. A later envelope version must add an evidence-manifest digest once the evidence-manifest capability exists.
- Canonicalization uses RFC 8785 JCS and is tested for deterministic output. Do not sign arbitrary API JSON, database serialization, or a representation that can change between runtimes.
- The server exposes the exact canonical signing bytes to the decision author, verifies submitted signatures using registered public keys and persists the signature, key ID/fingerprint, algorithm, signing-envelope version and envelope digest.
- Private keys are generated and retained by the operator or their approved key-management system. DeviceTrust must never store private keys or expose a server-side signing endpoint.
- Public keys are registered to an active managed operator principal through an offline administrative workflow. Key rotation, expiry, revocation and historical verification must be explicit.
- A managed API token authenticates a request; it is not proof that the holder controls the signing key. Both checks are required.
- A valid signature proves possession of a registered private key over the signed bytes. It does not by itself prove a person's civil identity, employment, authority to represent a manufacturer or correctness of the decision.

### 2. Independent second-person approval

- A decision requiring approval remains pending until a distinct active operator principal approves the exact decision digest.
- The author cannot approve their own decision, including through a second credential. The approver must authenticate with a managed principal and provide a valid signature from a separately registered Ed25519 key whose purpose is decision-approval.
- Approval signs a domain-separated RFC 8785 envelope containing the decision digest, decision/finding/revision identity, approval purpose, approver principal, key ID/fingerprint, timestamp and policy version.
- The initial `devicetrust.approval-policy.v1` requires one currently trusted author signature plus at least one distinct active operator approval. The implementation issues a server-timestamped payload with a 30-minute acceptance window and persists approval plus audit event in one transaction.
- Mathematical signature validity, current key/principal trust and eligibility for the current decision revision are reported separately. Revocation, principal disablement, loss of the author signature's trust or a newer decision revision prevents current policy satisfaction.
- Any new decision revision invalidates approval of the superseded revision for current export purposes; historical signatures and approvals remain immutable and verifiable.
- Approval policy is explicit and versioned. The initial policy is one author signature plus one distinct approver signature; it is not described as organizational quorum or legal sign-off.
- VEX export must require the current revision to meet the configured approval policy. There is no implicit approval and no fallback to the author.

### 3. Evidence integrity and provenance verification

- Keep evidence references opaque and never dereference arbitrary user-supplied URLs from the API.
- Persist a bounded per-artifact manifest record that binds an observation to a server-generated artifact UUID, SHA-256 digest, media type, byte length, uploader actor and server recording time. The current implementation stores 1–5 MiB artifact bytes as a database BLOB and does not derive a filesystem path from user input.
- Compute SHA-256 over exact received bytes; never accept a client-supplied artifact digest as the authoritative digest. Recompute digest and byte length on verification and before content download.
- Reject unsupported declared media types and oversized/empty uploads. Serve untrusted bytes only as an attachment with `application/octet-stream` and `nosniff`.
- Commit artifact metadata, bytes and audit event in one transaction; identical observation/digest/media-type uploads are idempotent.
- Preserve separate states for byte integrity, signature verification, source authentication and claim review. The current artifact workflow establishes only stored-byte integrity; it does not authenticate source or claim.
- Artifact records are linked to observations, not yet to exact vulnerability decision revisions. Existing decision evidence references remain opaque.
- A digest detects byte mismatch against stored metadata, not source identity or factual correctness. A privileged database writer can replace both bytes and digest. Independent anchoring and source-specific signatures remain future work.

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

1. **Signature foundation (implemented in PR #58):** canonical domain-separated envelope, Ed25519 verification, operator-bound public-key registry, offline registration/revocation and signature re-verification. The implementation uses `cryptography` and keeps private keys outside DeviceTrust. RFC 8785 canonicalization is used by the implementation; independent cross-language test vectors and a formal key-custody runbook remain follow-up work.
2. **Decision signing (initial implementation in PR #58):** an author can attach one verified detached signature to an immutable decision revision; historical unsigned records remain explicitly unsigned. Making a signature mandatory for every new decision is not yet enforced.
3. **Second-person approval (integrated through PR #62):** separate approver identity and purpose-specific key; domain-separated approval envelope; exact decision digest/revision binding; versioned one-author-plus-one-independent-approver policy; immutable history and dynamic trust/eligibility evaluation.
4. **Evidence artifact integrity (PR #64; CI validated, integration pending):** bounded observation-linked artifact BLOBs, server-computed digest/size, integrity re-verification, fail-closed downloads and transactional audit metadata. Exact decision-revision binding, artifact signatures, source authentication and external anchoring remain follow-up work.
5. **Audit anchoring:** signed checkpoint format, independent verifier, then one explicitly supported external immutable-storage integration.
6. **VEX export:** only after the signature, approval, evidence and BOM-reference preconditions are enforced and tested.

Each stage is a separate implementation change with migration, threat-model update, tests and documented operational procedure. Do not bundle all stages into one large migration or claim a control is implemented merely because its schema exists.

## Security requirements and acceptance criteria

- Private-key material never appears in API requests, logs, database rows, audit payloads, CI artifacts or repository files.
- Signature verification rejects altered payloads, wrong key purpose, unknown/revoked keys, mismatched principals, unsupported algorithms and unsupported envelope versions.
- Canonicalization has published test vectors and produces identical bytes across supported runtimes.
- An author cannot approve their own decision, including through a second credential belonging to the same principal.
- Approval is invalid for current export eligibility after a new decision revision is appended.
- The author cannot approve their own decision using another credential or key; approval requires a distinct active operator and a key registered for decision-approval purpose.
- Approval requires a currently trusted author signature and an approval payload within its bounded validity window.
- Evidence digest or byte-length mismatch is detected; content download fails closed. Current manifests do not yet establish source authentication, artifact signatures or exact decision-revision binding.
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
