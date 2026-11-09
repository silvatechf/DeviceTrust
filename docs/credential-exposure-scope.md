# Credential Exposure and Machine Identity — Product Scope

## Purpose

This document defines a proposed DeviceTrust capability for connected and embedded product teams. It is a product-scope proposal, not an implemented feature or a claim that DeviceTrust can currently detect, revoke or prevent credential compromise.

The intended value is to connect credential-exposure evidence to a declared product, release, artifact and accountable remediation workflow. DeviceTrust should complement specialised scanners, secret managers, PKI platforms and OT security controls rather than replace them.

## Problem to address

A credential leak can create a systemic exposure when one shared or overprivileged identity grants access to many devices or services. Relevant exposure classes include:

- API keys, service tokens and JWT signing material.
- Database connection strings and credentials.
- RTSP/ONVIF connection strings or other embedded service credentials.
- Private keys, certificates and machine identities.
- Default, shared or hardcoded credentials in source, configuration, build artefacts or firmware.

The impact depends on credential scope, privilege, reuse, validity, revocation capability, product/deployment context and compensating controls. A string match alone does not prove that a credential is active, valid, exploitable or deployed.

## Proposed DeviceTrust responsibility

DeviceTrust should maintain a traceable record of exposure signals and remediation evidence at product/release level:

1. Receive a bounded, normalised finding from an external scanner or an authorised operator.
2. Link the finding to a declared product, release and source artefact where that relationship is known.
3. Preserve source provenance, scanner/rule identity, observation time, artifact digest and coverage status.
4. Keep unverified claims distinct from reviewed conclusions.
5. Record an attributable decision, rationale, evidence references and remediation status after individual identity and authorisation exist.
6. Preserve assessment and decision history so a later scan does not erase what was previously known.

Potential evidence sources include Gitleaks or equivalent repository/CI scanning, firmware-analysis tools, configuration reviews, Vault/secret-manager metadata, PKI inventory and operator-supplied incident records. Initial integrations should consume reports or metadata; they should not require DeviceTrust to hold the underlying secret.

## Data handling and security invariants

- **Never persist raw secrets.** Do not store API keys, passwords, bearer tokens, private keys, credential-bearing URLs or unredacted scanner output.
- Treat scanner output as untrusted input. Parse only supported, bounded schemas and normalise/redact before persistence.
- Do not use an ordinary unsalted hash of a secret as a safe substitute: low-entropy values can be guessed offline. Avoid retaining secret-derived fingerprints unless a later design demonstrates a protected, keyed construction and a clear operational need.
- Store only the minimum metadata needed to investigate: finding category, tool and rule, artifact digest, sanitised location, observation time, source, confidence/coverage and a non-secret external reference where appropriate.
- Keep source evidence and machine-generated findings separate from human-reviewed decisions.
- A scanner match is an exposure signal, not proof that a credential is live or compromised.
- A missing scanner finding or unavailable scanner is not proof that an artifact is clean.
- Do not attempt authentication, enumerate endpoints, retrieve video streams or test credentials against third-party systems.
- Do not automatically rotate, revoke or modify credentials. Those actions belong to the authoritative identity/secret-management system and require an explicitly authorised workflow.
- Never treat a product identifier, IP address, MAC address or hostname as proof of device identity.

## Proposed MVP boundary

The first useful slice should be ingestion and evidence management, not a new secret scanner or vault:

- Accept a documented, bounded report format from one selected secret-scanning tool.
- Validate the report envelope, size, finding count and supported finding fields.
- Reject or redact any secret-bearing fields before persistence; tests must prove raw values do not appear in database rows, API responses, logs or audit events.
- Associate findings only with an explicitly supplied product/release/artifact reference; otherwise retain them as unassigned evidence.
- Preserve tool, rule, source, timestamp, artifact digest, sanitised file location and scan coverage.
- Expose read-only finding history and explicit incomplete/unverified states.
- Defer human approval, remediation attestation and cross-tenant operation until identity, scoped authorisation and audit attribution are implemented.

A first integration candidate is a sanitised Gitleaks report from CI. The exact report contract and redaction behavior must be validated against the selected tool version before implementation. Do not assume all scanner formats are safe to ingest.

## Machine identity governance — later capability

A later phase may correlate product and deployment evidence about machine identities, including certificate metadata, issuer/subject/SAN, serial number, expiry, revocation status, mTLS configuration and secret-manager rotation metadata.

DeviceTrust must not become a certificate authority or secret vault. It should reference authoritative systems and retain evidence of ownership, scope, lifecycle and review. Private keys and secret values remain in their dedicated systems.

A meaningful machine-identity workflow requires individual operator identities, scoped authorisation, credential lifecycle and revocation controls, tenant boundaries and independently defensible audit evidence. The current shared API key is not sufficient.

## Explicit non-goals

This capability does not make DeviceTrust:

- A secret manager, password vault, PKI or identity provider.
- A network scanner, camera discovery service, RTSP/ONVIF client or video monitoring platform.
- An IDS/IPS, SIEM, EDR, SOAR or incident-response automation platform.
- A tool that proves credential validity, exploitation, device ownership or firmware authenticity.
- An automatic credential rotation/revocation service.
- A CRA conformity assessment or regulatory reporting system.

## Acceptance criteria for an implementation proposal

Before a first implementation is considered complete:

1. A supported scanner report can be ingested with strict size/schema limits.
2. Tests prove that representative API keys, passwords, JWT secrets, database URLs, RTSP URLs and private-key material are not persisted or emitted in responses, logs or audit events.
3. Each retained finding preserves provenance, artifact context and explicit coverage/uncertainty.
4. Unassigned or ambiguous product/release relationships are not guessed.
5. Duplicate ingestion is idempotent and historical observations remain immutable.
6. API access is appropriately scoped; reviewed decisions are impossible without attributable operator identity.
7. CI includes parser tests, secret-leak regression tests, dependency/static analysis and database migration coverage.
8. Documentation clearly distinguishes scanner signals, verified exposure, remediation evidence and residual risk.

## Product claim

A defensible future claim, after implementation and validation, would be:

> DeviceTrust helps product-security teams correlate credential-exposure signals with connected-product releases and retain traceable remediation evidence.

Until the acceptance criteria are met, this is a roadmap direction only. Current DeviceTrust does not provide credential-exposure detection or machine-identity governance.
