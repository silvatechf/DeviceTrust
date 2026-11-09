# DEC-009: Versioned KEV and EPSS enrichment

- Status: Implemented in PR #47; pending merge
- Date: 2026-11-08
- Scope: Product SBOM assessment enrichment

## Context

DeviceTrust stores immutable SBOM imports and append-only assessment runs. The current assessment workflow can produce component-scoped vulnerability findings from local demonstration advisories and optional OSV enrichment. It does not yet preserve CISA Known Exploited Vulnerabilities (KEV) or FIRST Exploit Prediction Scoring System (EPSS) observations.

KEV and EPSS are different signals:
- CISA KEV records vulnerabilities CISA identifies as known exploited in the wild. Catalog membership is a high-priority exploitation signal, not proof that a particular product release is affected.
- EPSS estimates the probability of exploitation activity in the next 30 days. It is not an environmental risk score and does not establish product impact.

## Decision

1. Enrich CVE-backed findings only. Findings without a valid CVE identifier remain explicitly not assessed by these providers.
2. Preserve each provider observation as part of the append-only assessment snapshot. Never overwrite an earlier assessment when feeds change.
3. Store provider status, source URL, retrieval timestamp, feed/model date, and source version where supplied.
4. Represent provider outcomes distinctly: disabled, complete, incomplete, and not-found/no-record. A missing record is not evidence of no vulnerability or no risk.
5. Bound network activity, response size, number of CVEs and total enrichment time. Provider failures must not erase local/OSV findings or turn an incomplete assessment into a clean result.
6. Treat KEV membership and EPSS score as prioritization inputs only. Do not derive an affected/not-affected decision, compliance conclusion, CRA reporting trigger, or VEX statement automatically.
7. Keep KEV and EPSS independently configurable so operators can disable either provider and the assessment can report the exact coverage obtained.

## Source contracts

### CISA KEV

Use the official CISA JSON catalog, with the CISA-maintained `cisagov/kev-data` GitHub mirror as a fallback when the canonical endpoint is unavailable. Record which endpoint supplied the snapshot and retain the canonical CISA source reference. Validate the top-level catalog version, release timestamp, declared count, vulnerability array, CVE identifiers and required date fields before accepting a snapshot. Retain only the fields required to explain the signal: CVE ID, vendor/project, product, date added, due date, ransomware-use indicator, required action, catalog version and release timestamp.

### FIRST EPSS

Use the FIRST API for bounded batches of CVE lookups. Validate CVE identifiers and parse score/percentile as finite decimal values in the inclusive range [0, 1]. Preserve the score date and retrieval timestamp. Do not treat percentile as a probability. Missing CVEs and provider errors must be distinguishable.

## Consequences

- Historical assessment results remain reproducible as recorded observations, subject to the limits of the source metadata.
- Fresh assessments can change as the KEV catalog and EPSS daily scores change.
- External data is best-effort; timeouts, malformed responses, unavailable feeds, and unscored CVEs remain visible as incomplete coverage.
- No provider result establishes package-to-CVE applicability by itself. Applicability remains dependent on the quality of the upstream finding and component/version matching.
- VEX remains out of scope until attributable human review and product-version-scoped decisions exist.

## References

- CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA-maintained KEV data mirror: https://github.com/cisagov/kev-data
- CISA KEV JSON schema: https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json
- FIRST EPSS API: https://api.first.org/data/v1/epss
- FIRST EPSS data guidance: https://www.first.org/epss/data
- FIRST EPSS FAQ: https://www.first.org/epss/faq
