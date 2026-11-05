# Engineering Decisions

This document records material architecture and security decisions for the DeviceTrust prototype. Each decision states context, choice, consequences and conditions for revisiting it.

## DEC-001 — Modular monolith for the prototype
**Status:** Accepted

**Context:** The product is an early-stage, single-team prototype with a small domain surface and no demonstrated need for independent service scaling.

**Decision:** Keep the API, domain services and persistence in one FastAPI modular monolith. Separate responsibilities into modules and service boundaries rather than introducing distributed services.

**Consequences:** Lower operational complexity and easier local testing; module boundaries must remain explicit to avoid a large, tightly coupled route module. Distributed deployment and independent scaling are not current capabilities.

**Revisit when:** Independent scaling, team ownership boundaries or availability requirements justify the operational cost of service decomposition.

## DEC-002 — Shared API key is a local prototype boundary, not user identity
**Status:** Accepted with production limitation

**Context:** The current workflow needs a simple authenticated API boundary for local evaluation.

**Decision:** Use a configured shared API key with constant-time comparison. Fail closed when the server key is absent. Do not interpret the key as an individual identity, role or tenant.

**Consequences:** Anyone holding the key has the same broad access. The browser console exposes the key to its local browser session and developer tools. No individual accountability, scoped authorization, revocation or tenant isolation exists.

**Revisit when:** Shared deployment, multiple operators, attributable approvals or external access are required. Add individual identity, scoped authorization and server-side sessions first.

## DEC-003 — Evidence observations remain separate from posture inputs
**Status:** Accepted

**Context:** Imported evidence can be incomplete, stale, conflicting, spoofed or derived from a shared upstream source. Automatically treating ingestion as proof would create false assurance.

**Decision:** Persist bounded observations with source and time provenance, default them to unverified, and expose a read-only normalized projection. Do not automatically associate observations or feed them into posture calculations.

**Consequences:** Raw observations remain traceable and normalization is reproducible. Unknown, invalid and unclassified values remain visible. Posture remains based on the existing declared profile; evidence currently adds context but does not change posture findings.

**Revisit when:** Per-control acceptance rules, freshness windows, conflict resolution, source independence and actor authorization are defined and adversarially tested.

## DEC-004 — Normalization is deterministic, versioned and non-destructive
**Status:** Accepted

**Context:** Sources represent attributes in different formats; normalization must not erase original claims or silently infer semantics.

**Decision:** Use pure normalizers for explicitly supported attributes. Preserve source attribute and raw value, return a canonical attribute and normalized value when valid, report invalid known values without coercion, and keep unknown attributes unclassified. Include a normalizer version.

**Consequences:** Unit tests validate normalization without database side effects. Consumers can reproduce the rules used. Unsupported attributes remain available for future adapters.

**Revisit when:** Source-specific adapters, stale-value rules or schema evolution require broader compatibility policy.

## DEC-005 — Bounded CycloneDX subset and explicit intelligence limits
**Status:** Accepted for MVP

**Context:** Full SBOM schema and ecosystem-specific vulnerability matching are substantial integration surfaces.

**Decision:** Accept a bounded CycloneDX JSON subset, enforce request and component limits, normalize PURLs, and use PURL-scoped synthetic demo advisories plus optional best-effort OSV lookup.

**Consequences:** Deterministic local demonstrations are possible. The local feed is not vulnerability intelligence. External lookup may fail or omit relevant results. Absence of a finding is not proof that a component is safe.

**Revisit when:** A production intelligence source, provenance model, caching policy, affected-range semantics and coverage monitoring are selected.

## DEC-006 — Hash-chain audit is tamper-evident, not immutable
**Status:** Accepted with explicit residual risk

**Context:** The prototype needs verifiable records of state-changing operations without claiming an independently protected audit platform.

**Decision:** Store SHA-256 hash-linked audit entries and expose verification. Document that the chain cannot detect deletion of its final entry or suffix, or privileged recomputation, without an external checkpoint.

**Consequences:** Modification and interior deletion can be detected when later links remain. A valid chain does not prove completeness. Concurrent writers need serialized chain-head updates before multi-worker use.

**Revisit when:** Audit assurance requires independently controlled checkpoints, signatures, WORM storage or stronger retention guarantees.

## DEC-007 — Same-origin console without persistent browser credentials
**Status:** Accepted for local demonstration

**Context:** A lightweight interface improves demonstrability without a separate frontend build and deployment stack.

**Decision:** Serve static console assets from FastAPI, use same-origin API calls, keep the shared key in page memory only, and apply restrictive console response headers.

**Consequences:** Simple local deployment and no browser-storage persistence for the API key. The key remains accessible to the browser session and developer tools. This is not a production session architecture or multi-user security boundary.

**Revisit when:** External or multi-user access is required; use server-side sessions or a backend-for-frontend with individual identity and appropriate CSRF controls.

## Decision review rule
Revisit a decision when new requirements or evidence invalidate its context, a residual risk becomes unacceptable, or before representing the prototype capability as production-ready. Add a new decision entry rather than silently rewriting historical rationale.
