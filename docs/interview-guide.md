# Interview Guide — Explaining DeviceTrust

Use this as a speaking aid. Explain what the code actually does; do not memorize claims that go beyond the implementation.

## 1. A 45–60 second introduction

"DeviceTrust is a Python/FastAPI prototype for IoT/OT security evidence and vulnerability triage. I use food production, processing and cold-chain operations as the initial application context because these environments rely on connected controllers, sensors and gateways, while their security and software-component information can be fragmented. The prototype brings device inventory, declared security posture, bounded evidence observations, supported SBOM analysis and justified triage into one traceable workflow. I chose a modular monolith because the current scope does not justify distributed services. A key design principle is that missing or unverified information stays unknown rather than being treated as safe. The current demo uses entirely synthetic assets and advisories; it is not a production scanner, intrusion-detection system or compliance certification."

## 2. Explain the architecture

1. A client or the local console sends an HTTP request to FastAPI.
2. Protected routes check the shared API key.
3. Pydantic validates typed request bodies; the SBOM endpoint applies its own streaming size limit and JSON validation.
4. Route handlers call domain code for posture, SBOM, normalization or audit behavior.
5. SQLAlchemy persists devices, evidence, findings and audit entries.
6. The API returns findings or reports to the client.

**Why one application?** It keeps local setup and testing simple. Microservices would add operational complexity without a current scaling or ownership requirement.

## 3. Explain the cold-chain demonstration

The synthetic scenario contains:

- `COLD-CTRL-001`: a refrigeration controller with some declared controls and unknown firmware-integrity evidence.
- `TEMP-SENSOR-002`: a cold-room temperature sensor with incomplete identity and security information.
- `EDGE-GW-003`: an industrial edge gateway with a stronger declared security profile and an illustrative CycloneDX SBOM.

The sample SBOM uses generic PURLs and matches deliberately synthetic `DT-DEMO-*` advisories. These are demonstration records, not real vulnerabilities or a verified bill of materials from a supplier.

The walkthrough shows inventory, uncertainty, supported SBOM processing, justified triage, reports and audit history. It does not show live discovery, temperature telemetry or control of refrigeration equipment.

## 4. Decisions worth defending

**Why focus on food production and cold-chain operations?** It is a concrete application context for connected controllers, sensors and gateways, and it maps to the current inventory/SBOM/triage workflow. This is a market hypothesis, not validated product-market fit. The first buyer hypothesis is OT/automation integrators and specialist consultancies serving food-sector operators.

**Why keep evidence unverified?** Receiving a claim is not the same as validating it. Router exports, device declarations and vendor responses can be stale or spoofed. Treating ingestion as verification would create false confidence.

**Why not associate a device by MAC or IP?** Those values can change or be spoofed. They are not reliable identity proof. Association needs stronger evidence and an attributable review process.

**Why a bounded CycloneDX subset?** The prototype needs a controlled SBOM workflow, not a claim of complete schema coverage. It enforces request and component limits and validates PURLs. Full schema/dependency-graph validation remains future work.

**Why a hash chain?** It can reveal modification of retained audit entries. It is not immutable: a privileged attacker can rewrite the database, and deleting the final suffix cannot be detected without an external checkpoint.

**Why a shared API key?** It is a basic local boundary for a single-operator demo. It is not suitable for multiple users or external deployment. Individual identity, authorization scopes and key lifecycle are prerequisites.

## 5. Security controls to point at

- Constant-time API-key comparison and fail-closed behavior when the server key is missing.
- Pydantic validation and bounded input fields.
- A 2 MiB streaming limit for SBOM request bodies.
- Server-controlled evidence verification state.
- Explicit `unverified` posture when information is missing.
- Console CSP and baseline response headers.
- Ruff, Bandit, pip-audit, pytest and CodeQL configuration.

For each control, explain its limitation. A configured CI workflow is not proof that a particular commit passed; inspect the run for the exact SHA.

## 6. What is not finished?

- Individual operator identity, RBAC and tenant isolation.
- Evidence-to-device association, conflict/freshness rules and evidence-driven posture.
- Full CycloneDX validation and complete vulnerability intelligence.
- External audit checkpoints and safe concurrent chain writes.
- Alembic migrations and verified PostgreSQL operations.
- Rate limiting, monitoring, backup/restore and deployment rollback.
- Real customer discovery, validated willingness to pay and a controlled pilot.

Being clear about these gaps is part of the engineering story, not something to hide.

## 7. Likely interview questions

**What was the hardest design decision?**  
Keeping evidence separate from posture. It is tempting to treat imported observations as facts, but that would create false assurance. I chose traceability and explicit uncertainty over automatic conclusions.

**How would you take it toward production?**  
First add individual identity and scoped authorization. Then define evidence acceptance/freshness rules, migrations, PostgreSQL integration tests, audit anchoring/concurrency, rate limiting, monitoring and backup/restore. I would not start by splitting it into microservices.

**How do you know it is secure?**  
I cannot claim that it is secure or production-ready. I can point to specific controls and tests, static analysis and documented residual risks. Those are evidence of engineering work, not a security guarantee.

**What would you improve first?**  
I would prioritize identity and authorization because they are prerequisites for attributable operator decisions and any shared deployment.

**Why not automatically patch an OT controller?**  
Operational continuity and safety matter. Changes to refrigeration or production equipment require asset-owner approval, maintenance planning, impact assessment and rollback. DeviceTrust currently does not execute physical or software remediation.

## 8. A useful answer structure

When asked about a feature, answer in this order:

1. **Problem:** what risk or user need does it address?
2. **Implementation:** which module or API path handles it?
3. **Decision:** why was this approach chosen?
4. **Evidence:** which test or workflow supports the claim?
5. **Limit:** what does it not guarantee?

Keep the explanation tied to code you can open and walk through.
