# Product Vision — DeviceTrust

## Vision

DeviceTrust aims to help teams responsible for connected and embedded products maintain an explainable, reviewable record of product-version security decisions.

**Product direction:** Product Security Intelligence & Evidence Management.

The product concept connects five things that are often handled across separate engineering and security workflows:

1. Product and release identity.
2. Software-component inventories and their provenance.
3. Vulnerability intelligence and version-aware assessment.
4. Human-reviewed decisions, including carefully constrained VEX output.
5. Evidence, approval and audit history tied to the exact decision revision.

DeviceTrust is an early-stage prototype. This vision describes the intended product direction, not a claim that every workflow is implemented or commercially validated.

## Problem hypothesis

When a vulnerability or component issue is disclosed, a manufacturer may need to determine which product releases contain the relevant component, understand whether the affected version applies, document the reasoning, obtain review and retrieve supporting evidence later.

The problem to validate is:

> Can a manufacturer explain, reproduce and retrieve the reasoning behind a product-version security decision without reconstructing it manually from disconnected tools and records?

The initial focus is this traceability and decision-evidence workflow—not a general-purpose vulnerability scanner, OT monitoring suite, compliance platform or autonomous remediation system.

## Initial users and customer hypothesis

**Primary customer hypothesis:** small and medium-sized manufacturers of products with digital elements, including industrial gateways, sensors and embedded controllers.

**Primary technical users:** Product Security / PSIRT engineers, firmware and engineering leads.

**Potential sponsors and stakeholders:** security managers, CISOs, product compliance and regulatory leads.

**Complementary users and channels:** product-security consultancies, OT security specialists and integrators. Their legal role must be assessed per engagement; a service provider is not automatically the manufacturer under the Cyber Resilience Act (CRA).

This segment is a hypothesis, not validated product-market fit, customer demand, revenue or willingness to pay. Validate it through 5–10 exploratory interviews and at least one bounded pilot opportunity before broadening the product.

## Product promise

DeviceTrust aims to connect product/version records, software-component intelligence, vulnerability assessment, reviewed security decisions and traceable evidence in one explainable workflow.

A successful operator workflow should make it possible to:

- Register a product and a specific release.
- Import a supported SBOM and inspect accepted component occurrences.
- Assess the imported inventory while preserving unknown and incomplete states.
- Review findings and record attributable decisions with justification.
- Attach evidence and bind it to the exact decision revision.
- Obtain a distinct second-person approval where policy requires it.
- Export a narrowly scoped, schema-valid VEX artifact only when all eligibility checks pass.
- Retrieve assessment, decision and audit history.

The existing API and CLI provide parts of this flow. A coherent operator-facing experience remains a delivery objective, not an implemented capability.

## Product areas

### 1. Products and releases
Maintain declared product identity and release context. Do not infer a relationship between a product release and a physical device or deployed instance without explicit, attributable evidence.

### 2. Components and SBOM
Accept supported SBOM formats, preserve source identifiers and provenance, and make unsupported or ambiguous data visible. CycloneDX JSON 1.5 support is currently bounded; broader format coverage is future work.

### 3. Assessment and intelligence
Correlate component occurrences with vulnerability intelligence using ecosystem-aware version semantics. Distinguish a provider match from confirmed product impact. Missing, stale or unsupported intelligence must remain visible as uncertainty.

### 4. Reviewed decisions
Record human decisions against immutable assessment findings, with actor attribution, rationale and evidence references. Do not turn scanner output or provider signals directly into a VEX conclusion.

### 5. Evidence, approval and VEX
Preserve evidence integrity and bind manifests to exact decision revisions. Signatures establish possession of registered keys, not legal identity or truth. Independent approval is a workflow control, not proof against collusion. VEX export remains narrow, deterministic and fail-closed.

### 6. Governance and audit
Use least-privilege API credentials, append-only records and tamper-evident audit history. External audit anchoring, human identity assurance, tenant isolation and production-grade operations remain future requirements.

## Product principles

- **Intelligence, not verdict:** show evidence, provenance, coverage and uncertainty; do not imply automatic safety or compliance.
- **Human accountability:** security decisions require an attributable actor and explicit rationale.
- **Revision binding:** signatures, approvals and evidence manifests refer to exact immutable decision revisions.
- **Fail closed:** ambiguous identity, unsupported semantics or missing required evidence must block high-confidence exports.
- **Least privilege:** API clients receive only the scopes required for their workflow.
- **Honest boundaries:** distinguish implemented behavior, prototype limitations and future intent.
- **No premature platform complexity:** retain the modular monolith until measurable needs justify another architecture.

## Architecture direction

The current architecture is a Python/FastAPI modular monolith using Pydantic, SQLAlchemy and Alembic, with SQLite as the local default and PostgreSQL integration coverage.

The API owns authentication, validation, persistence and domain behavior. The CLI and future CI integrations remain API clients; they must not access the database directly or duplicate parsing, assessment or authorization logic.

Current intelligence integrations include bounded local advisories, optional OSV lookup, CISA KEV and FIRST EPSS enrichment. Ed25519 signatures use operator-controlled keys kept outside the application. The current VEX slice exports CycloneDX 1.5 only under strict decision, evidence, signature and approval checks.

A minimal web UI and a GitHub Action are future delivery items. Neither should be built as a parallel business-logic layer.

## Delivery strategy and phase gates

### P0 — Consolidate the existing engineering workflow
- Finish and validate authenticated CLI SBOM import.
- Verify the complete API sequence from product/release registration through SBOM import, assessment, decision, evidence, approval, VEX and history.
- Keep API contracts, test matrix, README and continuity record aligned.
- Acceptance: a reproducible, documented API/CLI walkthrough with explicit limitations.

### P1 — Demonstrable operator workflow
- Use one synthetic product and release as the vertical slice.
- Build a minimal operator UI over existing API contracts; avoid dashboards and broad administration features.
- Cover SBOM import, assessment, findings, decision/evidence, signature/approval, VEX export and history.
- Add end-to-end tests and a clean runbook.
- Acceptance: an operator can complete the core demonstration without manually composing HTTP requests; all critical transitions are tested and ineligible VEX exports fail closed.

### P2 — Improve intelligence quality
- Add real-world and synthetic SBOM fixtures representative of target manufacturers.
- Expand PURL and version semantics incrementally, beginning with ecosystems demonstrated by interview evidence.
- Preserve unknown/ambiguous results and provider provenance.
- Evaluate additional intelligence sources and SPDX only when the canonical component model and validation fixtures justify them.
- Acceptance: documented coverage by ecosystem, tested version edge cases and no speculative matches.

### P3 — Interoperability and independent trust
- Consider OpenVEX after the CycloneDX workflow is stable.
- Evaluate upstream VEX ingestion and CSAF only against a concrete integration need.
- Prioritise one external audit checkpoint design (for example, RFC 3161 or a Merkle-based checkpoint) rather than implementing several trust mechanisms at once.
- Evaluate DSSE only if an identified consumer or ecosystem requires it.
- Acceptance: an independently verifiable exchange or checkpoint with a documented trust model and operational ownership.

### P4 — Multi-team operations
- Add automated reassessment, decision review/expiry and notifications only after their operational semantics are defined.
- Introduce human identity, MFA/SSO, RBAC and tenant isolation before multi-customer operation.
- Define backup/restore, monitoring, rate limits, incident response and deployment rollback.
- Treat firmware SBOM discovery as a separate research effort, not a dependency for the core workflow.
- Acceptance: documented security and operational controls tested in a deployment model that matches the intended users.

Phases are gated by evidence, not calendar dates. Do not start a later phase merely because a date has arrived.

## Market validation

Run 5–10 exploratory interviews with small and medium-sized connected-product manufacturers. Include product-security consultancies and specialist integrators as complementary perspectives.

Investigate concrete past workflows:
- How are product releases and their software components recorded?
- Is an SBOM available for each shipped version, and who owns its accuracy?
- How are new vulnerabilities mapped to shipped and supported versions?
- How are false positives, vendor backports and not-affected decisions justified?
- Where are decisions, evidence and approvals retained?
- Which tools already cover this workflow, and where does manual reconstruction remain?
- Who owns the budget and could sponsor a bounded pilot using authorised data?

Do not lead with a feature pitch. Continue with the manufacturer segment only if interviews reveal a recurring problem, an identifiable owner and a credible pilot path. Reconsider the segment if existing tools solve the problem adequately or the required integrations exceed the project's realistic scope.

## Success measures

- A reproducible end-to-end demonstration can be completed in under 10 minutes.
- Every exported VEX statement is linked to a specific release, assessment and reviewed decision.
- Required signature, independent approval and evidence checks block ineligible exports.
- VEX output is deterministic and validates against the vendored schema.
- Assessment coverage and unknown states are visible rather than silently treated as safe.
- At least 5 target-user interviews are completed and findings recorded; a pilot is pursued only when a real owner and authorised data are available.

These are proposed delivery and discovery measures, not achieved results.

## Explicit non-goals

- CRA compliance claims, conformity assessment, certification or automatic regulatory reporting.
- Replacing full SCA, PSIRT, vulnerability-management or OT-security platforms.
- Active network discovery, packet capture, device agents, IDS/IPS or attack prevention.
- Autonomous remediation or physical equipment control.
- SaaS or multi-tenant deployment before identity and isolation foundations.
- Microservices without demonstrated scaling or ownership pressure.
- Broad integrations without validated user demand.

## Regulatory and claims boundary

The CRA is relevant context, not a product badge. DeviceTrust does not determine legal applicability, establish manufacturer responsibilities, run legal reporting timers, submit ENISA notifications or perform conformity assessment. Vulnerability feeds and SBOM matches do not by themselves establish product impact or an Article 14 reporting condition.

Use [Market Positioning](market-positioning.md), [Prototype Limitations](prototype-limitations.md) and [Release Readiness](release-readiness.md) as the operational claims boundary.

## Risks and open questions

- **Market risk:** the traceability problem and willingness to pay are unvalidated.
- **Data risk:** manufacturers may not have accurate, release-specific SBOMs or stable identifiers.
- **Intelligence risk:** ecosystem semantics, vendor backports and source/binary relationships remain incomplete.
- **Trust risk:** signatures and digests do not prove legal identity, source authenticity or claim truth; the audit chain lacks external anchoring.
- **Operational risk:** human identity, tenant isolation, backup/restore, monitoring and rollback are not production-ready.
- **Scope risk:** UI, additional formats, intelligence sources and integrations can expand faster than the validated core problem.

The product should advance only when each phase reduces a demonstrated user problem without overstating the assurance the prototype provides.
