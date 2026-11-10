# DEC-013: Deterministic CycloneDX VEX export contract

- Status: Implemented prototype in PR #72; broader VEX workflows remain deferred
- Date: 2026-11-10
- Scope: Export reviewed product-release vulnerability decisions as a dedicated CycloneDX 1.5 VEX BOM

## Context

DeviceTrust already stores accepted CycloneDX 1.5 SBOM imports, product/release associations, component occurrences, versioned assessment findings, append-only review decisions, Ed25519 decision signatures, independent second-person approvals, and revision-bound evidence manifests.

These records are necessary inputs, but they are not by themselves a valid VEX publication. Provider observations, severity, KEV/EPSS signals, version comparisons, and missing findings must never be converted into a manufacturer impact statement. A VEX statement must remain attached to a precise product/release, vulnerability, component occurrence, and current reviewed decision.

CycloneDX 1.5 represents vulnerability analysis with `analysis.state`, optional `justification`, `response`, `detail`, and issue timestamps. `affects[].ref` links the statement to a component or service by its `bom-ref`. The project currently imports only a bounded subset of CycloneDX and does not retain all source metadata needed for a complete round-trip.

References:
- [CycloneDX 1.5 JSON schema](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.5.schema.json)
- [CycloneDX VEX overview](https://cyclonedx.org/capabilities/vex/)

## Decision

### 1. Export form and scope

1. Generate a dedicated CycloneDX 1.5 VEX BOM, decoupled from the imported SBOM. The output is an export artifact, not a mutation of the original SBOM import.
2. Export for exactly one product release and one explicitly selected accepted SBOM import. Do not silently combine imports or assessment runs.
3. Include only the latest decision revision for each eligible assessment finding. Superseded revisions are history, not current statements.
4. The first implementation is a read-only deterministic export endpoint. It does not publish, distribute, submit or assert legal acceptance of the VEX.

### 2. Eligibility gates

A decision is exportable only when all of the following are true:

- The assessment finding belongs to an assessment of the selected accepted SBOM import.
- The finding's component occurrence belongs to that same import.
- The component has a non-empty preserved `bom-ref` that resolves uniquely within the selected SBOM.
- The vulnerability identifier is non-empty and suitable for CycloneDX `vulnerability.id`.
- The decision is the latest revision for that finding.
- The decision has a trusted, currently valid author signature bound to its exact decision revision and current evidence-manifest digest.
- The decision has a satisfied independent approval policy for that exact revision.
- The decision's state, justification and response values are in the supported CycloneDX 1.5 vocabulary.
- The assessment and import are accepted and internally consistent.

Any failed gate blocks that statement. The exporter must return a structured validation report and must not silently drop an ineligible decision from an otherwise successful export. A strict export either contains every selected eligible decision or returns a conflict explaining all blockers.

### 3. Product identity

1. Resolve the product and release from the selected import's foreign-key path; never accept product identity supplied by the export caller.
2. Use preserved `bom_metadata.metadata_component` as the VEX BOM `metadata.component` only when its type and name are present and valid.
3. Do not invent a product `bom-ref`, PURL, manufacturer authority, supplier identity, or hardware identity from the DeviceTrust database's free-text product fields.
4. If the imported BOM lacks a usable metadata component, block export until an explicit product-component identity mapping is introduced and reviewed.
5. Retain a provenance link to the source BOM using its preserved `serial_number` and BOM `version` when available. Missing source serial number is a blocker for the initial VEX export because an exact source BOM reference cannot otherwise be established safely.

### 4. Vulnerability and component mapping

1. Group statements by vulnerability identifier and identical analysis tuple (state, justification, response set and detail). If decisions for the same vulnerability identifier require conflicting analysis tuples in the same product release, block the export with an explicit conflict; do not merge incompatible states into one vulnerability object or emit duplicate ambiguous identifiers.
2. Map `VulnerabilityDecision.state` to `analysis.state`, `justification` to `analysis.justification`, `responses` to `analysis.response`, and `detail` to `analysis.detail`. The selected CycloneDX 1.5 schema must validate the resulting object; no internal state may be translated heuristically.
3. Set `analysis.firstIssued` from the earliest exported decision revision timestamp and `analysis.lastUpdated` from the current decision timestamp. Timestamps must be UTC.
4. Emit `affects[].ref` only from the exact preserved component `bom-ref`. Never fall back to component name, PURL, ordinal, or version matching.
5. Do not invent vulnerability source names, source URLs, ratings, descriptions, affected-version ranges, or recommendations. Include optional vulnerability metadata only when a trustworthy source field is explicitly persisted and validated.
6. Do not map DeviceTrust internal applicability labels, OSV/KEV/EPSS signals, or comparison outcomes to VEX states or affected-version claims.
7. Block `resolved_with_pedigree` until DeviceTrust can emit and validate actual component pedigree evidence; opaque decision evidence references alone do not satisfy CycloneDX's pedigree semantics.

### 5. Determinism and integrity

1. Serialize JSON deterministically with RFC 8785 canonicalization for digest/signature purposes; the API response may expose ordinary JSON, but its digest is over the canonical payload.
2. Sort vulnerability statements and affected references by stable identifiers. Avoid database row order as an implicit contract.
3. Derive a stable VEX document serial number from a documented deterministic input or store an immutable export record; never generate a new random identifier on every identical retry.
4. Include the source BOM serial number/version, source import digest, selected assessment IDs, current decision IDs/revisions, signature envelope digests, approval envelope digests, and evidence-manifest digests in a DeviceTrust export provenance record. Keep proprietary provenance outside standard CycloneDX fields unless a documented CycloneDX property is used.
5. Do not claim that the export's digest, signature or approval establishes legal identity, manufacturer authority, source authenticity or truth of the underlying evidence.

### 6. Failure behavior and API boundary

- Export requires a managed operator with a dedicated `vex:export` scope; legacy shared-key actors and service principals cannot initiate it.
- Export is read-only and audited. It must not create or modify vulnerability decisions, assessments, signatures, approvals, manifests or imported SBOM data.
- Missing signatures, invalid/revoked/expired trust keys, stale decision revisions, missing or invalid evidence manifests, unsatisfied approvals, unresolved component references, incomplete source identity, and unsupported data must fail closed.
- The validation report may identify finding IDs and blocker codes, but must not expose secrets, private keys, or raw evidence artifact contents.
- The first slice must not support partial exports, arbitrary filtering, VEX import, OpenVEX, or external publication.

## Data and implementation implications

- The current model preserves the original SBOM serial number, BOM version, metadata component identity, and component `bom-ref`; the importer does not retain the full raw SBOM document.
- Decision signature and approval verification already expose trust state and bind to immutable decision revisions. The exporter must reuse these verification services rather than duplicate cryptographic logic.
- Evidence manifest integrity must be rechecked at export time. A digest stored earlier is not sufficient if the underlying artifact bytes or trust binding no longer validate.
- Current assessment findings store a component occurrence and vulnerability identifier. Optional vulnerability source metadata is not yet a complete normalized CycloneDX vulnerability object; do not fabricate absent fields.
- The first implementation blocks `resolved_with_pedigree` because the current component model does not preserve commit/diff pedigree data required to substantiate that state.
- The first slice returns a deterministic provenance record and derives the VEX serial number from canonical source and decision inputs; it does not persist export artifacts as a separate resource.

## Acceptance criteria

1. A selected import with no eligible decisions produces a clear empty-result response, not a fabricated "not affected" statement.
2. A current, signed, independently approved eligible decision maps to a valid CycloneDX 1.5 vulnerability analysis object and exact component `bom-ref`.
3. A decision against a component without a `bom-ref` is blocked; name/PURL fallback is forbidden.
4. A superseded revision is never exported.
5. A stale, revoked, expired, invalid, missing or wrong-principal signature/approval blocks export.
6. A missing, tampered or stale evidence manifest blocks export.
7. Product identity and source BOM linkage are taken only from the selected import and its persisted product/release relation.
8. Repeated export of unchanged source and decision state produces byte-identical canonical JSON and digest.
9. The endpoint is managed-operator-only, read-only, scoped, audited, and has negative tests for every eligibility gate.
10. The output validates against the official CycloneDX 1.5 JSON schema in CI.

## Consequences and deferred work

This contract deliberately makes export conservative. It may block many current records until source BOM identity, component references, evidence, signatures and approvals are all present and trusted. That is preferable to emitting ambiguous or unsupported VEX statements.

The implemented first slice is a narrow export of reviewed decisions, not a general-purpose VEX authoring platform. It validates against the vendored CycloneDX 1.5 JSON schema and records an audit event for each export request. Full SBOM round-tripping, source authenticity, vendor backport semantics, service targets, multiple CycloneDX versions, OpenVEX and external publication remain out of scope.
