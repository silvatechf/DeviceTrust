# Threat Model

## Scope

The prototype manages device metadata, posture evidence, SBOM documents, vulnerability findings and audit events. It does not sit inline with device traffic and does not issue commands to physical controllers.

## Assets

- Device inventory and identifiers.
- Firmware and lifecycle metadata.
- SBOM documents and component versions.
- Vulnerability triage decisions.
- API credentials and authorization context.
- Audit history and evidence provenance.

## Trust boundaries

- External API clients to FastAPI.
- Uploaded SBOM documents to parser and persistence.
- Device-reported metadata to operator-verified evidence.
- Application to external vulnerability intelligence services.
- Application database to backup and audit-storage systems.

## Threats and gaps

| Threat | Current mitigation | Gap / planned work |
|---|---|---|
| Unauthorized API access | Shared API key | Per-client identities, rotation, RBAC |
| Malformed or oversized SBOM | Component-count limit | Body-size limit and full CycloneDX schema validation |
| Incorrect CVE matching | Local matcher and optional OSV | Version-range and ecosystem-aware matching |
| False compliance from missing data | `unverified` state | Evidence source, timestamp and confidence |
| Internet-exposed management | Explicit posture fields | Evidence source and observation timestamp |
| Unsupported firmware | `support_until` | Vendor-backed product/model lifecycle records |
| Audit database rewriting | Hash chain | External signed checkpoints and append-only storage |
| Compromised API key | Constant-time comparison | Identity-scoped credentials and least privilege |

## Safety boundary

A DeviceTrust alert does not stop an attacker from changing a physical device. Prevention and safe operation must be enforced by manufacturers, secure configuration, network segmentation, independent safety controls and engineered operational procedures.
