# Prototype Limitations

DeviceTrust is an early-stage engineering prototype. The following boundaries must be reflected in portfolio descriptions and technical discussions.

## Identity and access

- Managed authentication supports individual operator/service principals, expiring and revocable API credentials, keyed token verifiers and explicit route scopes. Legacy shared-key mode remains the default for backwards compatibility.
- There is no human login, MFA, SSO/OIDC, tenant isolation or customer-facing role hierarchy.
- Credential and signing-key administration is offline CLI only; no HTTP credential-management API exists.
- The local console receives the configured API token in page memory. This is not a production browser-session architecture.
- Managed principals identify configured technical actors, not legally verified humans.

## Decision signatures and approval

- Ed25519 detached signatures are supported for exact immutable vulnerability decision revisions. Private keys remain outside DeviceTrust; public keys are registered to operator principals and can be expired or revoked.
- Independent second-person approval uses a distinct active operator principal and a separately registered approval-purpose key. The initial policy requires a trusted author signature plus one independent approval; implementation in the current feature branch is pending CI/review/integration.
- Signatures prove possession of registered keys, not civil identity, manufacturer authority or the truth of a decision.
- Approval policy cannot prevent collusion or prove organizational independence. No legal sign-off or qualified electronic signature is provided.
- Signatures and approvals are not yet mandatory for every decision and are not consumed by a VEX exporter.

## Evidence and posture

- Device security fields are declared metadata, not independently measured or attested facts.
- Evidence observations default to `unverified`.
- Observations may be unassigned; the application does not infer identity or automatically associate them.
- Normalization covers selected attributes only.
- Stale/conflicting evidence is not resolved.
- Evidence observations do not currently feed posture calculations.
- A supplied artifact digest does not prove source authenticity or claim truth.
- Evidence manifest integrity, artifact signature verification and source authentication are not implemented.

## Vulnerability intelligence

- The CycloneDX parser accepts a bounded subset, not the complete schema or dependency graph.
- Local `DT-DEMO-*` advisories are synthetic demonstration data.
- Optional OSV lookup is best-effort and does not guarantee complete coverage.
- Ecosystem-specific affected-version semantics need broader validation.
- KEV and EPSS are prioritization signals, not product applicability or VEX decisions.

## Audit and operations

- SHA-256 hash chaining is tamper-evident, not immutable.
- Deletion of the final audit entry/suffix and privileged database rewrite can evade detection without an external checkpoint.
- Application writers are serialized through the audit-chain state row on SQLite and PostgreSQL; external database writers that bypass the application are outside this coordination.
- SQLite is the default; PostgreSQL migration, persistence and transactional integration are covered by CI, but production operations are not demonstrated.
- Alembic migrations are in place; every schema change still requires a reviewed migration and rollback procedure.
- Rate limiting, operational alerting, backup/restore, disaster recovery and production rollback are not demonstrated.

## Product boundary

- No active LAN scanning, packet capture or device agents.
- No inline IDS/IPS, attack prevention or physical safety control.
- No CRA conformity assessment, certification or regulatory reporting.
- No CycloneDX VEX export; VEX remains gated on evidence integrity and external audit assurance.
