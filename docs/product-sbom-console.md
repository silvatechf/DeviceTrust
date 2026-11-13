# Product SBOM Console

## Purpose

The operator console exposes a browser workflow for the Product / Release SBOM domain. It is intentionally separate from the legacy device-scoped SBOM screen.

The console is a client for the existing DeviceTrust API. It does not parse CycloneDX, persist product state, perform vulnerability matching, or make authorization decisions in JavaScript.

## Workflow

1. Connect to a trusted local DeviceTrust API instance.
2. Register a product with its manufacturer and product name.
3. Register a release against the returned product ID.
4. Import a CycloneDX JSON document against the returned release ID.
5. Inspect the import status, component count, and content SHA-256.
6. Load import history for the release.
7. Select an accepted import and start an assessment.
8. Inspect assessment history and retrieve findings for an assessment.

The API enforces the 2 MiB request limit. The console also checks the selected file size before upload. Import validation remains authoritative on the API.

## Authentication and authorization

The console sends the API credential in the `X-API-Key` request header. The credential is held in page memory only and is cleared when the operator disconnects or reloads the page. Do not expose this prototype console or its API to the public internet.

In managed-authentication mode, the operator credential needs these scopes for the complete workflow:

- `inventory:write` — create products and releases.
- `sbom:write` — import CycloneDX.
- `sbom:read` — inspect imports.
- `assessment:write` — start assessments.
- `assessment:read` — inspect assessment history and findings.

Legacy API-key mode continues to use the configured shared key and does not provide per-credential scope isolation.

## Current limitations

- There are no product or release list endpoints in the current API contract. The console displays newly created IDs and accepts IDs manually after a reload.
- Assessment requests use a fresh cryptographically generated idempotency key for each explicit operator action. A retry after a lost response is therefore a new request, not an automatic replay of the original idempotency key.
- The console currently displays findings using their vulnerability ID, severity, source, component record ID, and applicability. It does not yet provide component-name enrichment or decision/signature/approval controls.
- This workflow has not been manually validated end-to-end in a browser against a running local API. CI checks do not replace that validation.

## Security boundaries

- API authorization and domain validation remain server-side.
- API keys are not written to localStorage or sessionStorage.
- User-controlled values are inserted as text nodes, not interpreted as HTML.
- The existing Content Security Policy is unchanged.
- Product SBOM imports and assessments use the existing audit and persistence paths.
