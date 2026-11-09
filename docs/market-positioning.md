# Market Positioning — Product Security Intelligence

## Strategic decision

Position DeviceTrust as **Product Security Intelligence & Evidence Management**: a lightweight workflow concept for organising product identity and version context, software-component information, vulnerability assessment, reviewed security decisions and traceable evidence across connected and embedded products.

### Initial customer hypothesis

Small and medium-sized **manufacturers of products with digital elements** are the primary customer hypothesis. Examples include manufacturers of industrial gateways, sensors, connected controllers and embedded products.

Product-security consultancies, OT security specialists and integrators are complementary users and potential channels. Their legal role must be assessed per engagement: a service provider or integrator is not automatically the manufacturer under the Cyber Resilience Act (CRA).

Food production, processing and cold-chain infrastructure remain the synthetic demonstration context. They are not the boundary of the product concept.

This is a strategic hypothesis, not validated product-market fit, customer demand, revenue or regulatory qualification.

## Problem hypothesis

Manufacturers need to maintain context across product models and releases, software components, vulnerability information, security decisions, support periods and evidence. These records can be fragmented across engineering, suppliers, security teams and product documentation.

The core problem to validate is:

**When a new vulnerability or component issue is identified, can a manufacturer determine which product versions may be affected, explain the assessment, record the decision and retrieve supporting evidence without reconstructing the process manually?**

DeviceTrust should focus on that traceability problem rather than attempting to become a general-purpose vulnerability scanner, OT monitoring suite or compliance automation platform.

## Use case hypothesis: credential exposure across connected products

A compromised shared API key, service token, database credential or camera/streaming credential can create a fleet-wide exposure when identity scope is broad and product/deployment boundaries are weak. The relevant product-security question is not only whether a secret-like string exists, but which product release or artefact it relates to, what evidence supports the finding, who owns the credential, and whether rotation or revocation has been evidenced.

A future DeviceTrust workflow could correlate **external credential-scanning signals and machine-identity evidence** with declared product releases, artefact digests and accountable remediation records. Potential inputs include sanitised repository/CI secret-scanning reports, firmware-analysis results, PKI/certificate inventory and metadata from an existing secret manager.

This is a complementary product-security evidence workflow, not a replacement for Gitleaks, firmware-analysis tools, HashiCorp Vault, PKI, identity providers or OT security controls. DeviceTrust should not store secret values, private keys or credential-bearing URLs; it should not attempt logins, enumerate cameras, retrieve video streams, rotate credentials or enforce network segmentation.

The first implementation should ingest a bounded, sanitised report from one selected scanner and preserve provenance, artifact context, coverage and uncertainty. Human review and remediation attribution depend on individual operator identity and scoped authorisation, which are not currently implemented. See [Credential Exposure and Machine Identity scope](credential-exposure-scope.md).

**Current capability boundary:** credential-exposure detection, secret-manager integration, machine identity governance, mTLS enforcement and automatic rotation/revocation are not implemented. This use case is a roadmap hypothesis, not a current product claim.

## Regulatory context — EU Cyber Resilience Act

Regulation (EU) 2024/2847 establishes cybersecurity requirements for products with digital elements. It is relevant context for the product direction, but it is not a shortcut to a compliance claim.

Important boundaries:

- The CRA entered into force on 10 December 2024.
- Article 14 reporting obligations apply from 11 September 2026.
- The main CRA obligations apply from 11 December 2027, subject to the Regulation's transitional provisions and scope.
- Article 14 reporting concerns actively exploited vulnerabilities contained in products with digital elements and severe incidents affecting product security. It is not triggered automatically by every scanner result, CVE match, KEV entry or high EPSS score.
- Reporting has defined deadlines and must use the CRA Single Reporting Platform. DeviceTrust does not integrate with that platform and must not start legal reporting timers or submit notifications.
- The CRA includes obligations beyond SBOM creation, including product risk assessment, secure-by-design requirements, vulnerability handling, security updates, technical documentation and support-period considerations.
- Applicability, product classification, exclusions, manufacturer role and legal obligations require case-specific assessment.

A vulnerability feed can support awareness and investigation, but it does not by itself establish that a vulnerability is contained in a particular product, is actively exploited in that product, or meets an Article 14 reporting condition. Manufacturer awareness and product context matter.

DeviceTrust's intended role is limited to supporting engineering evidence and reviewed decisions. It is not a conformity assessment, legal opinion, certification tool or regulatory reporting channel.

## Target users and buying roles

| Segment / role | Potential need | Expected relationship |
|---|---|---|
| Small and medium-sized product manufacturers | Product/version/component traceability and vulnerability decisions | Primary customer hypothesis |
| Product Security Engineer / PSIRT | Component impact analysis, VEX and decision evidence | Primary technical user |
| Engineering / Firmware Lead | Release contents, dependencies and support context | Technical stakeholder |
| CISO / Security Manager | Risk visibility, governance and audit evidence | Sponsor or buyer |
| Product Compliance / Regulatory Lead | Retrievable technical evidence and process records | Influencer; not a substitute for legal assessment |
| Product-security consultancy | Repeatable assessments across clients | Complementary user / channel |
| OT or automation integrator | Product and deployment context at customer sites | Complementary user / channel |

## Product promise

**DeviceTrust aims to connect product/version records, software-component intelligence, vulnerability assessment, reviewed security decisions and traceable evidence in one explainable workflow.**

The current prototype does only a small part of this promise: device inventory, declared posture, bounded evidence ingestion, a bounded CycloneDX parser, limited advisory matching, justified triage, reports and hash-linked audit history.

## Initial demonstration context

Use the existing food-processing / cold-chain scenario to make the workflow tangible without implying a vertical lock-in:

1. Register synthetic refrigeration controller, temperature sensor and industrial edge gateway records.
2. Show declared attributes and preserve missing information as unverified.
3. Import the synthetic CycloneDX SBOM for the edge gateway.
4. Show limited matches against deliberately synthetic DT-DEMO-* advisories.
5. Record a justified triage decision.
6. Generate a report and verify the audit chain.

All identities, vendor names, package identifiers, SBOM contents and local advisories are fabricated. They are not real supplier data, real product firmware, confirmed vulnerabilities or a validated customer environment.

## Product concept: Product Security File

A future **Product Security File** could be a versioned, exportable record for each product release, containing:

- Product identity: manufacturer, model, product identifier, hardware/firmware/software release and support period.
- Software supply chain: SBOM format/version, components, identifiers, provenance, digest and import history.
- Vulnerability assessment: advisories, affected-version reasoning, KEV/EPSS context and assessment timestamps.
- Security decisions: triage, VEX statements, rationale, reviewer/actor and supporting evidence.
- Lifecycle and audit: product-version history, changes, decisions and integrity checkpoints.
- Reporting preparation: reviewed information that may help an authorised manufacturer prepare a notification.

This is an internal product concept, not an official CRA document, a complete technical file, proof of conformity or an implemented capability.

## Competitive boundaries and potential differentiation

DeviceTrust must not claim to replace established software-composition analysis, vulnerability-management, PSIRT, product-security or OT-security platforms.

Potential differentiation to validate:

- A focused workflow for smaller connected-product manufacturers that need product/version-to-component traceability.
- Explicit provenance and uncertainty rather than presenting imported data as verified facts.
- A reviewed chain from component finding to product impact assessment, decision rationale and evidence.
- A lightweight evaluation path that may complement existing engineering and security tools.

These are hypotheses. No competitive advantage, market gap or willingness to pay has been demonstrated yet. Interview target users before investing in broad integrations or a multi-tenant service.

## Market discovery plan

Conduct 5–10 initial exploratory interviews, then expand only if a repeatable problem emerges.

Prioritise:
- Product-security or firmware leads at small and medium-sized manufacturers of connected products.
- Manufacturers of industrial gateways, sensors and embedded controllers.
- Product-security consultancies and specialist integrators supporting those manufacturers.

Ask for concrete examples:
- How are product releases and their software components recorded?
- Is an SBOM available for each shipped version? Who owns its accuracy?
- How is a newly disclosed vulnerability mapped to shipped products and supported versions?
- How are false positives, backports and non-affected decisions justified?
- How are decisions, evidence, reviewers and customer communications retained?
- What triggers escalation to a PSIRT or regulatory/legal function?
- Which tools already cover the workflow, and where is manual work still required?
- Who owns the budget and could sponsor a bounded pilot?

Do not lead with a feature pitch. Look for recurring work, measurable cost or risk, a named owner, existing budget and willingness to test with authorised data.

### Validation gates

Continue with manufacturers as the primary segment if interviews show a recurring product/version/component traceability problem, an identifiable owner and willingness to run a bounded pilot.

Reconsider the segment if existing tools already solve the problem adequately, no reachable buyer owns it, SBOM data is unavailable in practice, or the required product integrations exceed the project's realistic scope.

## Claims policy

Allowed now:
- Python/FastAPI prototype for IoT inventory, declared security posture and vulnerability triage.
- Bounded CycloneDX JSON ingestion and limited PURL-based matching.
- Optional best-effort OSV lookup.
- Justified triage, JSON/Markdown reports and SHA-256-linked audit verification.
- Synthetic cold-chain demonstration.

Do not claim:
- CRA compliance, conformity assessment, certification or guaranteed compliance.
- ENISA CRA Single Reporting Platform integration or automatic regulatory notifications.
- Complete SBOM coverage, complete CVE coverage or verified product composition.
- Automatic Article 14 trigger detection or legal deadline management.
- VEX generation or product-version impact analysis before implemented and validated.
- Independent device/firmware attestation, active discovery, continuous monitoring, IDS/IPS or attack prevention.
- Production readiness, customer validation or product-market fit.

## References

- Regulation (EU) 2024/2847 — Cyber Resilience Act: https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng
- European Commission — Cyber Resilience Act: https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- European Commission — CRA reporting obligations: https://digital-strategy.ec.europa.eu/en/policies/cra-reporting-obligations
- ENISA — CRA Single Reporting Platform: https://www.enisa.europa.eu/topics/cybersecurity-policy/cra
- CycloneDX — VEX: https://cyclonedx.org/capabilities/vex/
- CISA — Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST — Exploit Prediction Scoring System: https://www.first.org/epss/
