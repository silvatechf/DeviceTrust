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

**Trade-offs:** Writers sharing one database are serialized, reducing concurrent write throughput. SQLite uses a database-level write reservation; PostgreSQL serializes on one row. Lock contention can delay or fail a write. The domain mutation, lock-row version update and audit append commit or roll back together.

**Security boundary:** This prevents concurrent application writers from forking the chain head. It does not prevent a privileged database administrator or external writer from rewriting the audit table, and it does not detect deletion of the final suffix without an independent checkpoint.

**Verification:** Concurrent SQLite and PostgreSQL writer tests, transaction rollback of the lock generation and audit append, and an unauthenticated-write check.
