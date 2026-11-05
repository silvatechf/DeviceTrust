# Persistent Product and SBOM Domain Design

**Status:** Proposed — requires review before schema implementation  
**Scope:** Milestone 3 (P1), linked to issue #18

## 1. Design objective

Create a traceable history from a product release to the exact SBOM import, component record and vulnerability finding that produced an assessment. A later SBOM import must not overwrite the earlier evidence.

This design is a proposal, not an implemented capability or a claim of CRA conformity.

## 2. Domain boundaries

Keep these concepts distinct:

- **Device:** an installed or managed physical/logical asset already represented by the current `devices` table.
- **Product:** a manufacturer-defined product family or product identity.
- **Product release:** a specific product version and, where relevant, hardware revision.
- **SBOM import:** one accepted ingestion event for a product release, with immutable provenance and parser outcome.
- **SBOM component:** a component occurrence in one specific SBOM import. It is a snapshot, not a globally deduplicated component identity.
- **Vulnerability finding:** an assessment result tied to the component occurrence and import that produced it.

A device is not automatically a product or a product release. Do not infer this relationship from device ID, hostname, MAC address, model name or vendor text. A future explicit deployment/asset-to-product-release association may be added only with a reviewed source and provenance.

## 3. Proposed relational model

```mermaid
erDiagram
    PRODUCT ||--o{ PRODUCT_RELEASE : has
    PRODUCT_RELEASE ||--o{ SBOM_IMPORT : receives
    SBOM_IMPORT ||--o{ SBOM_COMPONENT : contains
    SBOM_COMPONENT ||--o{ VULNERABILITY_FINDING : assessed_as
    DEVICE ||--o{ LEGACY_VULNERABILITY : has
```

### Product

Proposed fields:

- `id`: generated primary key.
- `manufacturer`: declared manufacturer name; not an independently verified identity.
- `product_name`: declared product name.
- `external_reference`: optional manufacturer-controlled identifier, stored as opaque text.
- `created_at`: UTC timestamp.

Do not make manufacturer/name a globally unique identity. Names can collide and change.

### ProductRelease

Proposed fields:

- `id`, `product_id` (foreign key).
- `version`: declared release/version string, preserved as supplied after bounded validation.
- `hardware_revision`: optional declared revision.
- `release_reference`: optional opaque manufacturer reference.
- `created_at`.

A uniqueness constraint should be based only on an explicitly selected manufacturer/product identity policy. Do not assume semantic versioning for every embedded product. Preserve version text; ecosystem-specific comparison belongs in later assessment logic.

### SBOMImport

Proposed fields:

- `id`, `product_release_id` (foreign key).
- `format` and `spec_version`.
- `source_type`: controlled value such as manual upload or pipeline import.
- `source_reference`: optional opaque reference; never fetched automatically.
- `content_sha256`: digest of the exact uploaded bytes.
- `imported_at`: server-recorded UTC timestamp.
- `parser_version`.
- `status`: explicit accepted/rejected/partial result.
- `component_count`, `warning_count`, bounded validation summary.

Do not store raw SBOM documents in the first iteration unless a retention, access-control and size policy is approved. A digest plus parsed snapshot gives traceability without silently introducing a document vault. If raw retention is later required, treat it as a separate security/storage decision.

### SBOMComponent

One row represents one component occurrence within one import:

- `id`, `sbom_import_id` (foreign key).
- `ordinal`: source position, stable within the import.
- `name`, `version`, optional `supplier`, optional `scope`.
- `purl`: original validated PURL string, nullable.
- Parsed PURL fields (type, namespace, name, version) may be stored only when parsing succeeds.
- Optional `bom_ref` as opaque source-local identifier, not a global identity.

Use a uniqueness constraint on `(sbom_import_id, ordinal)`. Do not globally unique components by name/version or PURL: the same component may occur in different releases/imports, and PURLs can be missing or ambiguous.

### Vulnerability finding

New product-release findings must reference `sbom_component_id` and `sbom_import_id` (the import may be derivable through the component, but a direct reference can simplify audit/report queries only if a consistency constraint guarantees they agree).

The existing `vulnerabilities` table is device-scoped and has a unique key on device/component/version/vulnerability ID. Do not repurpose it as a product finding table without a reviewed migration. Prefer a separate product-scoped finding model in the first implementation, or explicitly document and test a nullable-FK extension if a shared table is selected.

Legacy device findings remain valid with no inferred product/release association.

## 4. Import and idempotency semantics

1. Read the request with the existing streaming body-size cap.
2. Validate document shape, supported format/version and component bounds.
3. Compute SHA-256 over the exact request bytes, not a re-serialized JSON object.
4. Bind the import to an explicitly selected product release.
5. For an identical digest on the same release and format, return the existing accepted import (idempotent retry) rather than duplicating component rows.
6. A changed digest creates a new import record; prior imports and component snapshots remain unchanged.
7. Rejected/partial attempts should have explicit, bounded outcomes. Whether rejected attempts are persisted as import records or separate ingestion-attempt records must be decided before implementation; do not create misleading accepted imports.
8. Compare two accepted imports by component occurrence and canonical identifiers only where unambiguous. Report additions, removals, version changes and unresolved comparisons separately.

The digest is a content-integrity identifier, not proof of source authenticity or manufacturer authorship.

## 5. Identity and matching rules

- Valid PURL is the preferred package identifier for supported ecosystems.
- Preserve the original PURL and validate it; never silently rewrite an invalid PURL into a valid identity.
- Missing PURL does not mean the component is invalid. Retain bounded name/version/supplier fields but mark matching as limited.
- Never match across ecosystems using package name alone.
- Do not infer supplier from PURL namespace unless the data contract explicitly defines that interpretation.
- Preserve duplicate occurrences and source order; duplicate components may be meaningful in an SBOM.
- Do not claim that a PURL proves a component is actually present in a device.

## 6. Migration and compatibility strategy

- Add all new tables through a new Alembic revision; do not modify the already-applied baseline migration.
- Keep the existing `devices` and device-scoped SBOM endpoint behavior during the first migration.
- Do not backfill legacy device SBOM findings into product releases: current records do not contain reliable product/release provenance.
- Keep existing API response contracts stable until the new product-scoped endpoints are introduced.
- Add foreign keys, indexes and uniqueness constraints with SQLite and PostgreSQL behavior tested.
- Test migration upgrade and downgrade on disposable databases. A downgrade must not be presented as data-safe if it drops product/import history.

## 7. Security and privacy

- SBOM content is untrusted input. Preserve request and parser limits.
- Bound every persisted string and collection; avoid unbounded JSON payloads.
- Use parameterized ORM operations and explicit authorization dependencies on new endpoints.
- Do not expose raw source references or uploaded content by default.
- Keep secrets and credentials out of SBOM metadata, logs and audit payloads.
- Record who initiated an import only when a trustworthy actor identity exists. The current shared API key maps to a broad local actor, not an individual.
- Keep tenant isolation and multi-user claims out of scope until identity foundations exist.

## 8. Required tests

- Valid, malformed, oversized and unsupported SBOM documents.
- Missing, invalid and version-mismatched PURLs.
- Ecosystem collisions and same-name packages from different package types.
- Duplicate component occurrences within one import.
- Same digest imported twice for the same release.
- Same digest imported for a different release.
- Changed digest creates a new immutable import and preserves old components.
- Component diff with added, removed, version-changed and unresolved identities.
- Foreign-key integrity and transaction rollback on partial failure.
- SQLite migration upgrade/downgrade and PostgreSQL integration.
- Existing device-scoped import, finding, triage and report tests remain valid.

## 9. Proposed decisions for design review

The current implementation does not provide trustworthy manufacturer identifiers or individual actor identity. The following defaults minimise false identity claims and preserve compatibility:

1. **Product identity:** use an internal generated ID as the authoritative database identity. Treat manufacturer, product name and optional external reference as declared attributes, not a natural key. Do not enforce global uniqueness on names. When no trustworthy manufacturer identifier exists, keep potentially duplicate product records separate and expose duplicate detection as a review task; never auto-merge them. Product-release identity follows the same rule: preserve the declared version and optional hardware/release references, without assuming SemVer or inventing a cross-vendor uniqueness key.
2. **Rejected ingestion attempts:** do not create an `SBOMImport` for a document that fails validation before acceptance. Keep the import table semantically limited to accepted or explicitly partial snapshots. Return bounded validation errors and emit sanitised operational/security telemetry; do not log raw SBOM content. A separate ingestion-attempt entity is deferred until there is a concrete audit/retention requirement and a trustworthy actor model.
3. **Product findings:** introduce a separate product-scoped finding model referencing the exact `SBOMComponent` occurrence. Keep the existing device-scoped `vulnerabilities` table and its uniqueness semantics unchanged. This avoids nullable polymorphic ownership and prevents accidental migration of findings without product provenance.
4. **`bom-ref`:** preserve it as an opaque, import-local reference, but do not impose uniqueness in the first iteration. Duplicate or missing values must not collapse component occurrences; `(sbom_import_id, ordinal)` remains the occurrence key. If a future operation needs to resolve `bom-ref`, it must detect ambiguity and return an explicit unresolved result.
5. **CycloneDX contract:** initially support JSON only and the bounded component fields already represented by the parser. Before persistence is implemented, add explicit `specVersion` validation and fixtures for every version admitted by the API. Do not claim full CycloneDX schema support. The exact version allow-list must be selected in the implementation PR after checking the parser/library compatibility and fixtures; unsupported or missing versions must produce an explicit validation outcome.

These are proposed defaults, not implemented behavior. The implementation PR must encode the selected decisions in constraints, service-level invariants and tests. In particular, acceptance of partial imports, product duplicate review UX and the exact CycloneDX version allow-list remain explicit implementation decisions.

## 10. Explicit non-goals

- No automatic mapping from devices to products or releases.
- No global component identity registry.
- No KEV/EPSS enrichment, VEX export or CRA legal conclusions.
- No SPDX ingestion.
- No raw SBOM document vault.
- No SaaS, tenant isolation or multi-user authorization.
- No claims of complete SBOM validation or vulnerability coverage.

## References

- [Issue #18 — Persistent product releases, SBOM imports and component inventory](https://github.com/silvatechf/DeviceTrust/issues/18)
- [Current architecture](architecture.md)
- [Roadmap](roadmap.md)
- [Security controls](security-controls.md)
- [Release readiness](release-readiness.md)
