# Engineering Decisions

These are the main choices behind the current DeviceTrust prototype. Each one solves a specific problem, but also has a cost.

## DEC-001 — Modular monolith

**Decision:** Keep the API, domain logic and persistence in one FastAPI application, separated into modules.

**Why:** The project is small and has no proven need for independently deployed services. A modular monolith is easier to run, test and explain.

**Cost:** The code still needs clear module boundaries. Microservices may become useful later, but they would add operational complexity now.

## DEC-002 — Shared API key for local evaluation

**Decision:** Read `DEVICETRUST_API_KEY` from the environment, compare it with `hmac.compare_digest`, and fail closed when it is missing.

**Why:** This gives protected routes a basic authentication gate without a hard-coded default credential.

**Cost:** Anyone with the key has the same broad access. It provides no individual identity, roles, scopes, revocation, tenant isolation or attributable approvals. The browser console can access the key during its active session.

**Next step:** Add individual identity and scoped authorization before supporting multiple operators or external access.

## DEC-003 — Ingested evidence stays unverified

**Decision:** Store bounded observations with source and timestamps. The server assigns `unverified`; normalization is read-only. Observations do not automatically associate with devices or affect posture.

**Why:** Receiving a claim is not the same as validating it. Router exports, device declarations and vendor responses can be stale, spoofed or based on the same upstream source.

**Cost:** Evidence adds context but does not currently change posture results. There is no conflict-resolution or association workflow.

**Next step:** Define source trust, freshness, per-control acceptance rules and an attributable review process before using observations in posture calculations.

## DEC-004 — Normalize without losing the original

**Decision:** Use pure normalizers for selected attributes. Keep the submitted attribute/value, return a canonical value when a rule exists, report invalid known values and leave unknown attributes unclassified.

**Why:** Pure functions are easy to test. Preserving the raw input makes the transformation reviewable and avoids silently rewriting a source claim.

**Cost:** Coverage is limited. Unknown values remain unknown instead of being guessed.

**Next step:** Expand coverage only with explicit source and attribute rules.

## DEC-005 — Bounded CycloneDX support

**Decision:** Enforce a 2 MiB request cap and component/field limits, validate PURLs and match supported package identities against synthetic local advisories. Optional OSV lookup is enabled with `DEVICETRUST_OSV=1`.

**Why:** This provides a repeatable SBOM workflow without claiming full schema or vulnerability-intelligence coverage.

**Cost:** The local feed is synthetic. The parser does not validate the full CycloneDX schema or dependency graph. OSV is best-effort; no result does not mean no vulnerability exists.

**Next step:** Select a maintained intelligence source and define provenance, caching, affected-version semantics and coverage monitoring.

## DEC-006 — Hash chain for tamper evidence

**Decision:** Each audit entry includes the previous hash and a SHA-256 digest of its content. The application exposes verification.

**Why:** A change to a retained entry or a broken link can be detected.

**Cost:** Deleting the final entry or suffix is not detectable without an external checkpoint. A privileged attacker can rewrite the database and recompute the chain. This decision does not provide immutable/WORM storage.

**Next step:** Add independently controlled checkpoints before making stronger audit-integrity claims.

## DEC-007 — Same-origin console

**Decision:** Serve static console assets from FastAPI, use same-origin requests, keep the key in page memory and set restrictive response headers.

**Why:** It keeps the demo simple and avoids a separate frontend build/deployment stack.

**Cost:** The key remains accessible to the browser session and developer tools. This is not a production session or multi-user security model.

**Next step:** Use server-side sessions or a backend-for-frontend with individual identity and appropriate CSRF controls if external access is introduced.

## How to explain these choices

For each decision, explain the problem, why the current approach fits the prototype, what it costs and what evidence would justify changing it. The trade-off is part of the engineering work.

## DEC-007 — Transactional serialization of audit-chain writers

**Decision:** Add a singleton `audit_chain_state` row. Authenticated write requests acquire it before domain reads and hold it in the same transaction as the domain mutation and audit append. PostgreSQL serializes through the row update lock; SQLite begins an IMMEDIATE write transaction. Direct audit appends acquire the same lock if the current transaction has not already done so. A missing state row fails closed.

**Alternatives considered:**
- Optimistic compare-and-swap with whole-transaction retries: less time holding a lock, but substantially more complex SQLAlchemy/request retry semantics.
- External append-only audit service or queue: stronger isolation and potential external anchoring, but disproportionate operational complexity for the current single-operator prototype.

**Trade-offs:** Writers sharing one database are serialized, reducing concurrent write throughput. SQLite uses a database-level write reservation; PostgreSQL serializes on one row. Lock contention can delay or fail a write; SQLite's busy timeout and PostgreSQL's transaction-local lock timeout are both bounded to 10 seconds. The domain mutation, lock-row version update and audit append commit or roll back together.

**Security boundary:** This prevents concurrent application writers from forking the chain head. It does not prevent a privileged database administrator or external writer from rewriting the audit table, and it does not detect deletion of the final suffix without an independent checkpoint.

**Verification:** Concurrent SQLite and PostgreSQL writer tests, transaction rollback of the lock generation and audit append, and an unauthenticated-write check.

## DEC-008 — Versioned product SBOM reassessment

**Decision:** Keep an accepted SBOM import and its component occurrences as immutable source evidence. Represent each vulnerability reassessment as a separate run linked to that import. Store generated findings under the run, together with source, retrieval time, coverage status and bounded-query metadata. Never replace findings from an earlier run.

**Why:** Vulnerability intelligence changes independently of the submitted SBOM. Updating the original finding rows would erase what was known at import time and mix generated intelligence with operator decisions. A separate run makes the assessment reproducible and allows users to compare historical results.

**Triage boundary:** Assessment findings are machine-generated evidence, not human decisions. A later run must not silently inherit a previous status or justification. This slice will not add product-finding triage; a future reviewed-decision model must reference a specific assessment finding and record actor, rationale and evidence. Existing device-scoped vulnerability triage remains unchanged.

**Execution boundary:** Reuse the existing local matcher and bounded OSV query path. Perform external enrichment before opening the persistence/audit transaction or acquiring the audit writer lock. Persist the run, findings and audit event atomically after enrichment. A failed persistence transaction must not leave a partial run.

**Idempotency:** Each run has an explicit request identity and source/configuration fingerprint. Repeating the same request for the same import must return the existing run rather than creating duplicate history. A deliberate refresh with a new request identity may create a new run even when the feed contents happen to be unchanged.

**Coverage semantics:** Persist `disabled`, `complete` or `incomplete` enrichment status and the existing failure, deadline, query-budget and skipped-PURL metadata. A missing finding or unavailable feed is never evidence that a component is safe. A run records the assessment time; it does not claim a globally consistent OSV snapshot because the public API may change during the run.

**Trade-offs:** The schema and API become more explicit, but historical runs increase storage. The current synchronous request model remains bounded but can still occupy an API worker for up to the enrichment budget. The current exact PURL/version query does not provide ecosystem-aware affected-version or backport semantics.

**Out of scope:** Background scheduling, parallel fan-out, KEV/EPSS, VEX, SPDX, broad CycloneDX schema support, automatic triage inheritance and production-readiness claims.

**Verification:** Test historical immutability, idempotency, duplicate/concurrent requests, incomplete/disabled coverage, partial findings, transaction rollback and PostgreSQL persistence.
