# Market Positioning — Agri-food IoT/OT Security

## Decision

DeviceTrust will remain a horizontal IoT/OT security evidence and vulnerability-triage product, with an initial market focus on **food production, processing, storage and cold-chain operations**.

Agriculture and precision-farming environments remain an adjacent expansion area, not the first commercial wedge.

This is a positioning hypothesis to validate with prospective users. It is not evidence of product-market fit, customer demand, revenue or regulatory qualification.

## Why this market focus

Food and agri-food operations depend on connected operational assets: industrial gateways, sensors, refrigeration controllers, environmental controls, production equipment and software components. Weak asset visibility, unsupported firmware, incomplete component information and fragmented supplier records can make vulnerability assessment difficult.

The focus is supported by several external signals:

- On 4 November 2026, the European Commission and ENISA published a joint statement about cyber incidents affecting commercial refrigeration systems and similar devices in several EU Member States. This demonstrates that connected food-retail infrastructure is an active operational-security concern; it does not demonstrate that DeviceTrust detected or could have prevented those incidents.
- ENISA's 2026 threat landscape describes how digital dependencies expand attack surfaces and how geopolitical developments influence cyber activity against EU organisations.
- Research on smart-farming security describes technical and deployment-readiness gaps, including interoperability, validation environments and the transition from research prototypes to deployable solutions.
- The ACT4FOOD initiative demonstrates that food-supply-chain cybersecurity is already an active European innovation area. DeviceTrust must therefore avoid generic claims of comprehensive food-chain protection or AI-driven real-time detection.

These signals establish relevance, not market size or willingness to pay. Customer interviews and pilots are required.

## Initial customer segment

### Primary initial segment

**OT security integrators, industrial automation service providers and specialist cybersecurity consultancies serving food and beverage operators.**

Why start here:

- They can encounter similar asset and vulnerability-assessment problems across multiple customer sites.
- They understand industrial constraints and vendor diversity.
- They can assess whether an evidence-centric workflow complements existing network-monitoring and OT-security tools.
- A bounded pilot can be conducted with synthetic or explicitly authorised customer data.

### Secondary segment

Food and beverage manufacturers, cold-storage operators, refrigerated logistics providers and larger food retailers with internal IT/OT or security teams.

### Adjacent expansion

Agricultural technology providers and larger, digitally mature farming operations using connected irrigation, greenhouse controls, environmental sensors and edge gateways.

Small individual farms should not be the initial target without evidence of a repeatable buyer, budget and deployment model.

## Buyer and user roles

| Role | Primary concern | DeviceTrust relevance |
|---|---|---|
| OT Security Specialist | Asset context and vulnerability exposure | Technical user |
| IT / Infrastructure Manager | Device inventory and supplier dependencies | User and influencer |
| CISO / Security Manager | Risk prioritisation and evidence | Sponsor or buyer |
| Automation Integrator | Repeatable customer assessments | Potential channel partner |
| MSSP / OT Consultancy | Repeatable assessment workflow | Potential buyer and partner |
| Plant / Operations Manager | Continuity and safe maintenance | Operational stakeholder |

## Product promise

**DeviceTrust helps teams organise IoT/OT asset information, assess declared security posture, analyse supported SBOM inputs, document vulnerability triage and retain traceable evidence.**

It does not currently discover devices on networks, independently verify device identity or firmware, detect intrusions, predict attacks, control industrial equipment or provide production-grade continuous monitoring.

## Initial use case

### Food production and cold-chain asset security assessment

Use a controlled assessment dataset representing a food-processing or cold-storage site:

1. Import or register representative assets such as refrigeration controllers, industrial gateways, environmental sensors and edge devices.
2. Record declared manufacturer, model, firmware and selected security attributes.
3. Preserve missing or uncertain information as unverified.
4. Import a supported CycloneDX SBOM and inspect component findings.
5. Correlate supported component identifiers with the local synthetic demonstration advisories and, where enabled, best-effort OSV results.
6. Record justified vulnerability-triage decisions.
7. Produce a device report and review the audit history.

The demonstration must label synthetic devices, SBOMs and local advisories clearly. It must not imply live network discovery, real customer telemetry or validated vulnerability coverage.

## Competitive position

DeviceTrust is not currently a replacement for OT network-monitoring, asset-discovery, intrusion-detection or incident-response platforms.

Established vendors and initiatives already address parts of this space, including asset visibility, network monitoring, threat detection and food-sector cyber resilience. DeviceTrust should be positioned as a lightweight, evidence-oriented assessment and vulnerability-triage workflow that may complement existing tools.

Potential differentiation to validate:

- Clear provenance and uncertainty for imported asset/evidence data.
- A focused workflow connecting inventory, supported SBOM analysis, justified triage and reports.
- Lightweight local evaluation suitable for technical assessment and partner feedback.
- Explicit separation between declared claims, observations and independently verified facts.

No competitive advantage is proven yet.

## Why agriculture is not the first wedge

Precision agriculture is strategically relevant, but it is a broad and fragmented environment with diverse device types, connectivity models, suppliers and operational contexts. A farm-level buyer may also have different budgets and security maturity from an industrial food processor or cold-chain operator.

The current DeviceTrust prototype is more closely aligned with centrally managed assets, gateways, component inventories, SBOMs and documented vulnerability decisions than with field-level discovery or agricultural process monitoring.

Agriculture remains in scope as a later vertical, particularly through AgTech integrators and larger operations. It should not dominate the first product narrative until interviews establish a repeatable buyer and concrete workflow.

## Roadmap implications

### Now — prove the assessment workflow

- Keep the existing prototype scope accurate.
- Build a reproducible food-processing / cold-chain demonstration using synthetic data.
- Improve the domain model and sample records only where needed to represent generic IoT/OT assets accurately.
- Document provenance, confidence, verification state and operational criticality as distinct concepts.
- Validate the workflow with OT integrators and food-sector security practitioners.

### Next — improve asset and vulnerability intelligence

- Define safe import formats and integrations for external asset inventories.
- Expand SBOM ecosystem/version semantics and record intelligence provenance and freshness.
- Define a defensible risk-prioritisation model that combines technical severity, exposure, asset criticality and evidence confidence.
- Add reviewed evidence-to-asset association and conflict handling only with suitable identity and authorisation controls.

### Later — controlled operational integrations

- Evaluate passive discovery integrations and read-only network telemetry sources.
- Add monitoring of asset and vulnerability changes.
- Introduce production-grade identities, RBAC, tenant isolation, operational controls and external audit checkpoints before multi-customer operation.
- Keep physical control and automatic remediation out of scope unless a separate safety and authorisation case is established.

## Market validation plan

Conduct 15–20 discovery conversations across:

- OT/automation integrators serving food and beverage customers.
- OT security consultancies and MSSPs.
- Security, infrastructure and operations leaders at food processors, cold-storage operators and larger retailers.

Ask about the current asset-inventory process, sources of firmware/software information, SBOM availability, vulnerability triage, supplier coordination, reporting effort, existing tools and purchasing authority.

Do not lead with a feature pitch. Seek evidence of a recurring workflow problem, current workaround, measurable cost or risk, budget owner and willingness to run a bounded pilot.

### Validation gates

Proceed with the food/cold-chain wedge if interviews show a repeated, costly assessment or evidence-management problem that existing tools do not adequately solve and at least one qualified organisation agrees to a controlled pilot.

Reconsider the initial vertical if the problem is already fully handled by incumbent tooling, if no reachable buyer owns it, or if the required integrations exceed the project's realistic scope.

## Claims policy

Allowed now:

- IoT/OT security evidence and vulnerability-triage prototype.
- Inventory and declared-posture assessment.
- Bounded CycloneDX ingestion and limited vulnerability matching.
- Justified triage, reports and hash-linked audit history.

Do not claim:

- Active or complete device discovery.
- Real-time monitoring or intrusion detection.
- Prevention of cyberattacks or nation-state sabotage.
- Prediction of attacks or operational failures.
- Complete CVE coverage or verified device security.
- NIS2/CER/CRA compliance, certification or guaranteed compliance.
- Production readiness or validated customer outcomes.

## References

- European Commission, Joint statement on cyber incidents in refrigeration systems across the EU, 4 November 2026: https://digital-strategy.ec.europa.eu/en/news/joint-statement-cyber-incidents-refrigeration-systems-across-eu
- ENISA, Threat Landscape 2026: https://www.enisa.europa.eu/topics/cyber-threats/threat-landscape
- ENISA, Cybersecurity of Critical Sectors: https://www.enisa.europa.eu/topics/cybersecurity-of-critical-sectors
- European Commission, NIS2 Directive: https://digital-strategy.ec.europa.eu/en/policies/nis2-directive
- ACT4FOOD — Advanced Cybersecurity Tools for Critical Food Supply Chains: https://act4food.eu/
- Systematic mapping study on security for IoT-based smart farming systems, Computers & Security, March 2026: https://doi.org/10.1016/j.cose.2025.104790
