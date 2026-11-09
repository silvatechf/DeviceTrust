# DEC-011: Preserve CycloneDX identity for future VEX linkage

- Status: Implemented prototype in the SBOM reference-preservation branch; pending review and merge
- Date: 2026-11-09
- Scope: Product-release SBOM imports and future standalone CycloneDX VEX references

## Context

A standalone VEX needs to identify the precise product/component occurrence to which a vulnerability decision applies. CycloneDX uses component bom-ref values for references, and BOM-Link can identify an element in an external BOM by its serial number, BOM version and component reference.

The product SBOM importer previously retained component name, version and PURL, but discarded the original BOM serial number, BOM version, metadata component identity and component bom-ref. The raw SBOM document is not retained, so those references could not be reconstructed reliably later.

## Decision

Preserve the minimum source identity needed for future, reviewable VEX linkage:

- Store the CycloneDX top-level serialNumber and version when supplied.
- Preserve a bounded identity snapshot of metadata.component (type, bom-ref, name, version and PURL).
- Preserve each top-level component's optional bom-ref.
- Reject malformed serial numbers, invalid BOM versions, invalid references and duplicate bom-ref values within the parsed top-level BOM identity.
- Keep bom_metadata separate from enrichment and assessment intelligence.
- Bump the product SBOM parser version to 0.4.0.
- Do not synthesize a reference when the source BOM did not provide one.

## Migration and compatibility

Migration 0008 adds sbom_imports.bom_metadata and nullable sbom_components.bom_ref.

- Existing imports receive an empty BOM metadata object and NULL component references.
- Existing raw SBOM documents are not available to backfill those values.
- New imports preserve supplied identity fields without changing the original content digest or assessment snapshots.
- The import and component APIs expose the preserved fields.

## Consequences and limitations

- New imports can be linked to their original BOM when a serial number, BOM version and component reference are present.
- Components without bom-ref remain explicitly unreferenced; PURL-based fallback semantics are not invented in this change.
- Nested component graphs are not newly supported by this parser change; preservation applies to the currently parsed top-level component set.
- No human-reviewed vulnerability decisions, VEX export, signature or CRA conclusion is generated.
- The next decision workflow must bind each review to an immutable assessment finding and an accountable managed principal. A not_affected decision must require a valid CycloneDX justification and supporting rationale/evidence.

## References

- CycloneDX bom-ref uniqueness and vulnerability affects.ref: https://cyclonedx.org/docs/1.7/json/
- CycloneDX VEX and external BOM linkage: https://cyclonedx.org/guides/sbom/relationships/
- CycloneDX vulnerability analysis states and justifications: https://cyclonedx.org/docs/1.7/json/
