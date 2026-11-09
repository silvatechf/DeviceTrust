# Identity and Access Governance

## Status

Implemented prototype capability; PR #50 was merged into main. Managed authentication is opt-in through DEVICETRUST_AUTH_MODE=managed; the backwards-compatible default remains legacy. This is not a production identity provider or a multi-tenant access system.

## Principal and credential model

A principal represents an accountable operator or machine integration.

- Principal IDs are immutable UUIDs.
- Principal kinds are operator or service.
- Principals can be active or disabled.
- Each API credential belongs to exactly one principal.
- Credentials have a unique non-secret prefix, a keyed HMAC-SHA256 token verifier, an allow-listed scope set, creation/expiry timestamps and a revocation timestamp.
- Tokens contain 256 bits of cryptographically generated entropy. The raw token is displayed only by the offline creation command and is never stored.
- Credentials expire after 90 days by default; the creation service rejects expiries beyond 365 days.
- Authentication checks the keyed credential verifier, expiry, revocation and principal status on every request. No positive authentication cache is used.

The HMAC verifier uses a 32-byte hex pepper supplied through DEVICETRUST_CREDENTIAL_PEPPER. Configure the same pepper for the API process and offline CLI, and keep it outside the database. This is a machine-token verifier, not a password hashing strategy. Human passwords are not supported. Managed authentication fails closed with 503 if the pepper is missing or malformed.

## Authentication modes

### Legacy mode

DEVICETRUST_AUTH_MODE=legacy is the default for backwards compatibility. It requires DEVICETRUST_API_KEY and preserves the historical audit actor api-key. This remains a single shared trust domain and is unsuitable for multi-operator deployment.

### Managed mode

Set DEVICETRUST_AUTH_MODE=managed. Requests must provide a valid individual token in the existing X-API-Key header. The legacy environment key is ignored completely; there is no fallback. Missing/invalid credentials return 401, insufficient scope returns 403, and unavailable managed-auth persistence returns 503.

Unknown authentication modes fail closed with 503.

## Route scopes

The route-to-scope policy is explicit in app/identity.py. A protected route without a matching policy is denied. Current scopes:

- inventory:read, inventory:write
- evidence:read, evidence:write
- sbom:read, sbom:write
- assessment:read, assessment:write, assessment:review, assessment:sign
- audit:read
- credentials:manage (reserved for future API-based credential administration)

Decision-signature submission requires the separate assessment:sign scope and the same active operator principal that authored the decision. The signing key must be registered to that principal and use the decision-signing purpose. Signature reads require assessment:read. Reports require inventory:read, assessment:read and audit:read. Human review routes require the dedicated assessment:review scope and an active operator principal; service principals and legacy shared-key actors are rejected. Read permissions do not imply write permissions. The policy test checks that all routes depending on authentication have an explicit mapping.

## Offline administration

Apply migrations before using the CLI:

    alembic upgrade head

Generate a 32-byte random pepper (for example with Python secrets.token_hex(32)), store it as DEVICETRUST_CREDENTIAL_PEPPER in the deployment secret store, and make it available to both the API and CLI processes.

Create a principal and credential. Repeat --scope for each allowed scope:

    python -m app.identity_cli create-principal --name "Local operator" --kind operator --scope inventory:read --scope inventory:write --scope evidence:read --scope evidence:write --scope sbom:read --scope sbom:write --scope assessment:read --scope assessment:write --scope audit:read

The command prints the raw token once. Store it in an approved secret manager or local secret store; do not commit it or place it in shell history. To issue a separate reviewer credential to an existing operator, grant the review scope explicitly:

    python -m app.identity_cli issue-credential --principal-id PRINCIPAL_UUID --scope assessment:read --scope assessment:review --scope assessment:sign

Only active operator principals can create human review decisions; service principals and legacy shared-key requests are rejected. The CLI also supports offline Ed25519 public-key registration and revocation. Supply a PEM public key file only; private keys must never be passed to DeviceTrust:

    python -m app.identity_cli register-signing-key --principal-id PRINCIPAL_UUID --public-key-file operator-ed25519-public.pem --expires-in-days 365
    python -m app.identity_cli revoke-signing-key --key-id SIGNING_KEY_UUID

The CLI also supports:

    python -m app.identity_cli issue-credential --principal-id PRINCIPAL_UUID --scope inventory:read --scope audit:read
    python -m app.identity_cli revoke-credential --credential-id CREDENTIAL_UUID
    python -m app.identity_cli disable-principal --principal-id PRINCIPAL_UUID

Principal creation, credential issuance/revocation and principal disablement append audit events in the same database transaction as the identity change. The actor for offline administration is the fixed value offline-admin; it does not prove the OS user's identity.

For managed mode, configure DEVICETRUST_AUTH_MODE=managed in the API process and submit the generated token using X-API-Key. The console keeps the token in page memory only.

## Detached decision-signature workflow

1. Generate an encrypted Ed25519 private key and public key on the operator-controlled workstation. For example, OpenSSL prompts for a private-key passphrase:
   
       openssl genpkey -algorithm ED25519 -aes-256-cbc -out operator-ed25519-private.pem
       openssl pkey -in operator-ed25519-private.pem -pubout -out operator-ed25519-public.pem

   Keep the private key outside DeviceTrust and register only the PEM public key with the offline CLI. Protect and back up the private key using the organization's approved key-custody process.
2. Retrieve the exact canonical signing bytes from GET /sbom/decisions/{decision_id}/signing-payload?key_id=... using a managed credential with assessment:sign. Only the decision author can retrieve this payload. The response contains signing_payload_base64.
3. Decode and sign the payload locally. Example shell workflow:

       curl --fail --silent --show-error -H "X-API-Key: $DTK" --get --data-urlencode "key_id=$KEY_ID" "$DEVICETRUST_URL/sbom/decisions/$DECISION_ID/signing-payload" -o signing-payload.json
       python -c "import base64,json; p=json.load(open('signing-payload.json', encoding='utf-8')); open('decision-envelope.bin','wb').write(base64.b64decode(p['signing_payload_base64'], validate=True))"
       openssl pkeyutl -sign -rawin -inkey operator-ed25519-private.pem -in decision-envelope.bin -out decision-signature.bin
       SIGNATURE=$(python -c "import base64; print(base64.b64encode(open('decision-signature.bin','rb').read()).decode('ascii'))")

   DeviceTrust never receives the private key.
4. Submit the Base64 detached signature and key ID to POST /sbom/decisions/{decision_id}/signature. The request body contains only key_id and signature; never submit a private key.
5. Read GET /sbom/decisions/{decision_id}/signature to re-verify the stored signature against the current decision bytes. The response exposes the detached signature and public key for independent verification. signature_valid describes cryptographic validity; trust_valid additionally requires the key to remain active.

The signed envelope uses RFC 8785 JCS, UTF-8 and a domain separator. It binds the exact decision revision, reviewer principal, finding, state, rationale, evidence references, responses and timestamp. The signature endpoint is idempotent for an identical signature; a different signature for an already signed decision is rejected. A new decision revision is a separate unsigned record and must be signed separately.

The API token authenticates the request; the detached signature proves possession of the registered private key. Neither is legal identity proof or manufacturer authority.

## Audit attribution and data handling

Managed requests are attributed to principal:UUID. The actor is derived exclusively from the server-side credential lookup. Existing api-key audit events are retained unchanged. Raw tokens and request authorization values are not written to audit payloads.

The CLI never prints a token on revocation or disablement. Database access remains a privileged trust boundary.

## Verification

The implementation includes tests for managed token authentication, read/write scope separation, multi-scope reports, legacy-key rejection while managed mode is active, credential revocation, principal disablement, expired credential rejection, keyed token-verifier persistence and scope allow-list validation.

CI must pass SQLite migration/tests and PostgreSQL migration/persistence tests before this change is considered validated. These checks do not prove production readiness.

## Limitations

- Legacy mode remains the default until deployment/client migration evidence supports changing it.
- Credential lifecycle administration is offline CLI only; credentials:manage has no HTTP management endpoints yet.
- Rotating DEVICETRUST_CREDENTIAL_PEPPER invalidates every existing token verifier. Coordinate a maintenance window and issue replacement credentials to each principal after the pepper change.
- No human password, MFA, SSO/OIDC, session management, tenant isolation or customer-facing role hierarchy.
- No last-used tracking; adding per-request writes would create avoidable contention on the current audit/database transaction path.
- API tokens identify a configured principal, not a legally verified human.
- Ed25519 signatures prove possession of a registered private key over the canonical decision envelope, not civil identity, manufacturer authority or claim truth. Key revocation changes current trust status but does not erase historical cryptographic verifiability.
- Audit hash chaining remains tamper-evident, not immutable; independent external checkpoints are not implemented.
