# Product SBOM Console

## Purpose

The same-origin operator console exposes the Product / Release SBOM workflow. It remains a client of the DeviceTrust API: CycloneDX parsing, persistence, vulnerability matching, authorization and domain decisions stay server-side.

## Implemented browser workflow

1. Connect to a trusted local DeviceTrust API instance.
2. Register a product and release.
3. Import a bounded CycloneDX JSON document.
4. Inspect import status, component count and content SHA-256.
5. Load accepted import history for a release.
6. Start an assessment and inspect its history.
7. Retrieve findings for a selected assessment and inspect source-aware applicability metadata.
8. Submit an attributable human-review decision for an individual finding and retrieve its append-only decision history.

The API enforces the 2 MiB SBOM request limit; the console checks the selected file size before upload. API validation remains authoritative. Assessment and decision writes use fresh cryptographically generated idempotency keys for each explicit operator action. A retry after a lost response is a new request, not an automatic replay of the original key.

## Human review contract

The review form uses the existing `POST /sbom/assessment-findings/{finding_id}/decisions` and `GET /sbom/assessment-findings/{finding_id}/decisions` contracts. It submits the API-supported CycloneDX states, a rationale of at least 20 characters, optional justification, evidence references and an empty response list.

- `not_affected` requires a supported CycloneDX justification and at least one evidence reference.
- `resolved_with_pedigree` requires at least one evidence reference.
- Decision revisions are append-only; a new submission creates a new revision rather than editing an existing record.
- The API enforces actor attribution, managed-principal requirements, route scopes, validation and idempotency. The UI is not an authorization boundary.

## Authentication and authorization

The credential is sent in the `X-API-Key` request header, held in page memory only, and cleared when the operator disconnects or reloads the page. Do not expose this prototype console or API to the public internet.

The product/import/assessment workflow in managed-authentication mode requires:

- `inventory:write` — create products and releases.
- `sbom:write` — import CycloneDX.
- `sbom:read` — inspect imports and components.
- `assessment:write` — start assessments.
- `assessment:read` — inspect assessment history, findings and decision history.
- `assessment:review` — create human-review decisions.

Human decisions require an active managed operator principal. Legacy shared-key mode can perform the earlier import and assessment workflow but is rejected by the API for human-review writes. Managed mode also requires `DEVICETRUST_CREDENTIAL_PEPPER` to be configured for both the API and offline identity CLI.

## Current limitations

- There are no product or release list endpoints. The console displays IDs returned by creation and accepts IDs manually after a reload.
- The console does not yet enrich findings with component names; it displays the component occurrence ID.
- Evidence observation/artifact creation, artifact-to-decision manifest binding, author signature, independent approval and VEX export are not yet exposed as a complete browser workflow. Their existing API contracts remain authoritative.
- Signing and approval private keys must remain outside DeviceTrust. Any future browser-assisted signing must preserve local key custody and must never upload private key material.
- The current manual browser validation covers local API connection, Product SBOM import/history, assessment history and findings rendering. The human-review UI added in this change still requires a managed-mode browser walkthrough; automated API workflow tests do not replace it.
- No human login, MFA/SSO, tenant isolation, production session architecture or customer-facing RBAC is provided.

## Security boundaries

- API authorization and domain validation remain server-side.
- API keys are not written to localStorage or sessionStorage.
- User-controlled values are inserted as text nodes, not interpreted as HTML.
- The existing Content Security Policy is unchanged.
- Product SBOM imports, assessments and decisions use the existing persistence and audit paths.
- Evidence references are operator-supplied identifiers; recording a reference does not authenticate its source or prove its claim.
