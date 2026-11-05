# Interview Guide — Explaining DeviceTrust

Use this as a speaking aid. Explain what the code actually does; distinguish the current prototype from the product direction and do not claim planned capabilities as implemented.

## 1. A 45–60 second introduction

"DeviceTrust is a Python/FastAPI prototype exploring Product Security Intelligence and Evidence Management for connected and embedded products. The customer hypothesis is small and medium-sized manufacturers that need to understand which product releases may be affected by software-component vulnerabilities and retain evidence for their decisions. The current prototype implements device inventory, declared security posture, bounded evidence ingestion, a limited CycloneDX parser, advisory matching, justified triage, reports and hash-linked audit history. I use a synthetic food-processing and cold-chain scenario to demonstrate the workflow, but the product concept is not limited to that vertical. The design principle is to preserve provenance and uncertainty rather than turn imported claims into verified facts. DeviceTrust is not a CRA compliance tool or production security platform."

## 2. Explain the architecture

1. A client or the local console sends an HTTP request to FastAPI.
2. Protected routes check the shared API key.
3. Pydantic validates typed request bodies; the SBOM endpoint applies its own streaming size limit and JSON validation.
4. Route handlers call domain code for posture, SBOM, normalization or audit behavior.
5. SQLAlchemy persists devices, evidence, findings and audit entries.
6. The API returns findings or reports to the client.

**Why one application?** It keeps local setup and testing simple. Microservices would add operational complexity without a current scaling or ownership requirement.

## 3. Explain the current demonstration

The synthetic scenario contains:

- `COLD-CTRL-001`: a refrigeration controller with some declared controls and unknown firmware-integrity evidence.
- `TEMP-SENSOR-002`: a cold-room temperature sensor with incomplete identity and security information.
- `EDGE-GW-003`: an industrial edge gateway with a stronger declared security profile and an illustrative CycloneDX SBOM.

The sample SBOM uses generic PURLs and matches deliberately synthetic `DT-DEMO-*` advisories. These are demonstration records, not real vulnerabilities or a verified bill of materials from a supplier.

The walkthrough shows inventory, uncertainty, supported SBOM processing, justified triage, reports and audit history. It does not show live discovery, temperature telemetry or control of refrigeration equipment.

## 4. Explain the product direction

The product hypothesis is that a connected-product manufacturer needs a traceable relationship between:

- Product identity and release/version.
- The SBOM and component versions included in that release.
- Vulnerability intelligence and affected-version reasoning.
- Reviewed security decisions, including future VEX statements.
- Supporting evidence, decision actors and audit history.

The core question is: **when a new vulnerability is disclosed, which product releases may be affected, why, and what evidence supports the decision?**

This is a proposed direction. Persistent product/version records, component inventory, VEX export and KEV/EPSS enrichment are not implemented in the current prototype.

## 5. CRA: explain the boundary accurately

The Cyber Resilience Act is a relevant regulatory context for products with digital elements. Article 14 reporting obligations started applying on 11 September 2026; the main CRA obligations apply from 11 December 2027, subject to scope and transitional rules.

A scanner result, CVE match, KEV listing or EPSS score does not automatically establish an Article 14 reporting trigger. The manufacturer needs product-specific context and must assess whether the applicable condition is met. DeviceTrust does not determine legal applicability, start regulatory timers, submit notifications to ENISA or certify conformity.

The CRA covers much more than SBOMs: product risk assessment, secure-by-design requirements, vulnerability handling, updates, technical documentation and support-period obligations are also relevant.

## 6. Decisions worth defending

**Why focus on manufacturers?** Product manufacturers own product design, release composition, vulnerability handling and the relevant product obligations. A traceable product-version-to-component workflow is therefore a coherent problem hypothesis. It still needs validation with actual manufacturers.

**Why keep cold chain in the demo?** It is a concrete, understandable connected-product scenario with controllers, sensors and gateways. It demonstrates the current workflow without restricting the product concept to one industry.

**Why keep evidence unverified?** Receiving a claim is not the same as validating it. Supplier declarations and imported inventories can be stale or incomplete. Treating ingestion as verification would create false confidence.

**Why not associate a device by MAC or IP?** Those values can change or be spoofed. They are not reliable identity proof. Association needs stronger evidence and an attributable review process.

**Why a bounded CycloneDX subset?** The prototype needs a controlled SBOM workflow, not a claim of complete schema coverage. It enforces request and component limits and validates PURLs. Full schema/dependency-graph validation remains future work.

**Why a hash chain?** It can reveal modification of retained audit entries. It is not immutable: a privileged attacker can rewrite the database, and deleting the final suffix cannot be detected without an external checkpoint.

**Why a shared API key?** It is a basic local boundary for a single-operator demo. It is not suitable for multiple users or external deployment. Individual identity, authorization scopes and key lifecycle are prerequisites.

## 7. Security controls to point at

- Constant-time API-key comparison and fail-closed behavior when the server key is missing.
- Pydantic validation and bounded input fields.
- A 2 MiB streaming limit for SBOM request bodies.
- Server-controlled evidence verification state.
- Explicit `unverified` posture when information is missing.
- Console CSP and baseline response headers.
- Ruff, Bandit, pip-audit, pytest and CodeQL configuration.

For each control, explain its limitation. A configured CI workflow is not proof that a particular commit passed; inspect the run for the exact SHA.

## 8. What is not finished?

- Product identity, release/version model and persistent SBOM/component inventory.
- SBOM diffing and product-version-to-component traceability.
- KEV/EPSS enrichment and reviewed VEX export.
- Individual operator identity, RBAC and tenant isolation.
- Evidence-to-device association, conflict/freshness rules and evidence-driven posture.
- Full CycloneDX validation and complete vulnerability intelligence.
- External audit checkpoints and safe concurrent chain writes.
- Alembic migrations and verified PostgreSQL operations.
- Rate limiting, monitoring, backup/restore and deployment rollback.
- Customer discovery, willingness-to-pay validation and a controlled pilot.

Being clear about these gaps is part of the engineering story, not something to hide.

## 9. Likely interview questions

**What was the hardest design decision?**  
Keeping evidence separate from posture. It is tempting to treat imported observations as facts, but that would create false assurance. I chose traceability and explicit uncertainty over automatic conclusions.

**How would you take it toward production?**  
First establish Alembic migrations and PostgreSQL integration tests, then build the product/version/component data model. Before multi-user operation, add individual identity, scoped authorization and tenant isolation. Then address audit anchoring/concurrency, rate limiting, monitoring and backup/restore. I would not start by splitting it into microservices.

**How do you know it is secure?**  
I cannot claim that it is secure or production-ready. I can point to specific controls and tests, static analysis and documented residual risks. Those are evidence of engineering work, not a security guarantee.

**What would you improve first?**  
I would establish migration and persistence foundations, then model product releases and persistent SBOM components. Those are prerequisites for meaningful product-version impact analysis and VEX.

**Why not automatically submit CRA notifications?**  
Regulatory reporting depends on the manufacturer's awareness, product context and applicable legal conditions. A feed match is not enough. DeviceTrust should support reviewed evidence and preparation, not make legal determinations or submit notifications.

## 10. A useful answer structure

When asked about a feature, answer in this order:

1. **Problem:** what risk or user need does it address?
2. **Implementation:** which module or API path handles it today?
3. **Decision:** why was this approach chosen?
4. **Evidence:** which test or workflow supports the claim?
5. **Limit:** what does it not guarantee?

Keep the explanation tied to code you can open and walk through.
