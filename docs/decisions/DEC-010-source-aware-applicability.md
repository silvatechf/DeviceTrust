# DEC-010: Source-aware product-component applicability signals

- Status: Implemented prototype in the product applicability branch; pending review and merge
- Date: 2026-11-09
- Scope: Versioned product SBOM assessment findings

## Context

An SBOM finding is not automatically proof that a particular product release is affected. DeviceTrust receives findings from different sources with different assurance levels:

- OSV returns vulnerabilities for a supplied package and version query. The API performs ecosystem-aware upstream version matching, but its result remains a provider observation.
- Local demo advisories use synthetic records and a generic PEP 440 comparison. They are deterministic fixtures, not vendor-maintained affected-version ranges.
- Unknown or future finding sources may not provide enough evidence to classify applicability.

A single generic affected or not_affected state would conceal these differences and could be misused as a VEX conclusion.

## Decision

Persist an explicit applicability object on each versioned SBOMAssessmentFinding, separate from KEV/EPSS intelligence.

Supported statuses:

- osv_reported_affected: OSV returned the vulnerability for the component's package/version query. The record preserves the endpoint, versionless query PURL, original component PURL, queried version and observation time.
- synthetic_candidate: a local synthetic advisory matched through the existing generic PEP 440 fixed-version comparison. This is a demonstration candidate only.
- unknown: source evidence is absent, malformed or unsupported.

No automated not_affected status is produced. No-match responses, missing findings, missing PURLs, unavailable feeds or incomplete scans are not evidence that a component is unaffected.

## OSV query contract

OSV /v1/query accepts either a versioned PURL or an unversioned PURL with a separate top-level version. DeviceTrust uses the latter consistently:

- package.purl excludes the version segment.
- version is the exact version string from the SBOM component.
- PURL qualifiers and subpath are preserved.
- The query contract version is included in the assessment source fingerprint so an idempotency key cannot silently reuse a result created under the previous request shape.

OSV documents its version matching as fuzzy against upstream versions. An OSV match is therefore recorded as osv_reported_affected, not as a vendor-confirmed product impact decision.

## Data and API behavior

- Applicability is stored with each append-only assessment finding.
- Existing findings receive an empty JSON object during migration; historical assessment records are not reclassified retroactively.
- The findings API exposes the persisted applicability object.
- The original SBOM component, import and assessment snapshot remain unchanged.
- KEV and EPSS remain separate prioritisation observations and do not change applicability status.

## Consequences and limitations

- Reviewers can distinguish provider-reported matches from synthetic candidates.
- Missing or unsupported evidence stays unknown instead of becoming not affected.
- The implementation does not model vendor-specific backports, distro patch status, source/binary package relationships, firmware build provenance or all ecosystem-specific version schemes.
- No human-reviewed affected/not-affected decision, VEX statement, CRA conclusion or automatic reporting trigger is created.
- A future review workflow must require an accountable principal, rationale and supporting evidence before a not-affected decision can be recorded or exported.

## References

- OSV POST /v1/query: https://google.github.io/osv.dev/post-v1-query/
- OSV API: https://google.github.io/osv.dev/api/
