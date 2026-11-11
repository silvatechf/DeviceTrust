# Managed Identity Operations

## Purpose and status

This document describes safe local operation of DeviceTrust managed API credentials and signing identities. It complements [Identity and Access Governance](../identity-access-governance.md), which remains the source of truth for the identity model, route authorization policy and cryptographic contracts.

Managed authentication is an implemented prototype capability, but it is opt-in. The legacy shared-key mode remains the backwards-compatible default. These instructions are for a disposable local demonstration, not a production deployment procedure.

## Security model

- A principal is an accountable operator or service identity; each API credential belongs to one principal.
- The raw API token is generated once. DeviceTrust stores a keyed HMAC-SHA256 verifier, not the raw token.
- The verifier uses a 32-byte hexadecimal `DEVICETRUST_CREDENTIAL_PEPPER`. The same pepper must be available to the API and offline identity CLI.
- Managed credentials are individually scoped, expiring and revocable. Authentication checks credential and principal state on each request.
- Managed requests use the existing `X-API-Key` header. In managed mode the legacy `DEVICETRUST_API_KEY` is ignored; there is no fallback.
- The API token authenticates a request. It does not replace the separate Ed25519 detached signature used to sign a decision.
- Independent approval requires a distinct active operator principal and a separately registered approval key.

The current allow-listed scopes include `vex:export`. See `app/identity.py` for the authoritative allowlist and route-to-scope mapping.

## Local secret handling

### Ephemeral PowerShell session

For a disposable local walkthrough, environment variables can pass secrets to child processes without placing them in command-line arguments or repository files:

```powershell
$env:DATABASE_URL = "sqlite:///./devicetrust-p0-local.db"
$env:DEVICETRUST_AUTH_MODE = "managed"
$env:DEVICETRUST_CREDENTIAL_PEPPER = ( & .\.venv312\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))" ).Trim()
```

Keep the same PowerShell session open while using the API and CLI. Process environment variables are inherited by child processes and may be observable to processes running with the same user privileges; they are not a vault or a strong isolation boundary. Do not enable PowerShell transcription or share terminal recordings while secrets are present. Do not print the token or pepper for troubleshooting.

The raw token returned by `create-principal` should be captured directly into a process variable and then assigned to the environment variable used by the client. Clear temporary output variables after extracting the token:

```powershell
$env:DEVICETRUST_AUTHOR_TOKEN = $capturedAuthorToken
$env:DEVICETRUST_API_KEY = $env:DEVICETRUST_AUTHOR_TOKEN
$capturedAuthorToken = $null
```

Use a separate variable for the approver token. Do not reuse the author's credential for approval. Avoid writing tokens to files, clipboard history, shell command arguments, logs, screenshots, tickets or Git.

When the shell session is no longer needed, remove the secret variables:

```powershell
Remove-Item Env:DEVICETRUST_AUTHOR_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:DEVICETRUST_APPROVER_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:DEVICETRUST_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:DEVICETRUST_CREDENTIAL_PEPPER -ErrorAction SilentlyContinue
```

Closing the PowerShell process also ends that process environment. It does not remove credential verifiers or principals from the database.

### Persistent local or deployed use

For repeated use, retrieve secrets at runtime from an approved password manager or secret manager. Do not commit a `.env` file containing real credentials. Restrict access to the secret store and to the host identity that runs the API/CLI.

Pepper rotation is disruptive: the current implementation derives each stored verifier using the configured pepper. Replacing the pepper makes existing token verifiers unusable. Plan a coordinated credential re-issuance and deployment; do not rotate the pepper casually or assume multiple peppers are supported.

## Create separate operator identities

Apply migrations before offline identity administration:

```powershell
..venv312\Scripts\alembic.exe upgrade head
```

Create an author/operator principal with only the scopes required for its workflow. Repeat `--scope` for each permission. The full P0 product SBOM-to-VEX walkthrough needs the relevant inventory, SBOM, assessment, evidence, audit and VEX permissions; use the exact scope set documented in the current runbook and route policy.

Create a second, distinct operator principal for approval with only:

- `assessment:read`
- `assessment:approve`

Do not grant the approver authoring or signing permissions unless a separately justified workflow requires them. Do not use a second credential on the author's principal as a substitute for independent approval.

The offline CLI prints each raw token once. Capture it securely at creation time. If it is lost, issue a replacement credential and revoke the old credential; the original raw token cannot be recovered from the verifier.

Record non-secret principal and credential UUIDs in operational notes if needed. Never record raw tokens, the pepper, private keys or passphrases in those notes.

## API and CLI use

The API accepts the individual managed token in the `X-API-Key` request header. The authenticated CLI reads `DEVICETRUST_API_KEY` from its process environment; it must not receive the token as a command-line argument.

For the local author session:

```powershell
$env:DEVICETRUST_API_KEY = $env:DEVICETRUST_AUTHOR_TOKEN
$env:DEVICETRUST_API_URL = "http://127.0.0.1:8000"
```

The CLI's existing transport policy must remain in force: non-loopback API targets require HTTPS and redirects are not followed. Keep the local API bound to loopback for the synthetic walkthrough.

For approval requests, use the approver token in a separate request context. Never silently switch the author process to the approver identity or disclose either token.

## Ed25519 signing-key custody

Generate author and approver key pairs on the operator-controlled workstation. Keep private keys and their passphrases outside the repository in a directory protected by the OS account and appropriate filesystem permissions. Register only PEM public keys using the offline identity CLI.

Use separate keys and purposes:

- Author key: `decision-signing`, registered to the author principal.
- Approver key: `decision-approval`, registered to the distinct approver principal.

DeviceTrust receives only the public key and detached signature. The private key must never be uploaded, pasted into the API, committed, or passed to the application. Protect backups of private keys; loss of a key prevents future signing with that key, while compromise requires revocation and key replacement.

The exact canonical payload, signing commands, approval contract and trust semantics are documented in [Identity and Access Governance](../identity-access-governance.md). Follow those contracts rather than inventing a separate signing format.

## Verification and operational checks

Before treating a local setup as usable, verify all of the following without printing secret values:

1. The database is the intended disposable local database and is at the expected Alembic head.
2. Managed mode is enabled for both offline CLI and API processes.
3. The pepper is present and has the required 32-byte hexadecimal representation in both processes.
4. The author and approver are distinct active operator principals.
5. Each credential is associated with the intended principal, scopes and expiry.
6. The author can perform only the required author workflow; the approver can approve but cannot author the decision.
7. A revoked credential and a disabled principal are rejected.
8. The signing and approval public keys are registered to the correct principals and purposes.
9. The final VEX export is blocked until the current decision, evidence manifest, trusted author signature and independent approval satisfy policy.
10. Audit history records attributable principal actors without recording raw tokens or authorization headers.

Automated tests and a TestClient integration test do not replace a manual operator walkthrough against the local API process. Record the exact environment, commands, outcomes and limitations after the walkthrough; do not mark the P0 operator acceptance gate complete before that evidence exists.

## Troubleshooting safely

- **Token is unavailable:** raw tokens are not recoverable. Issue a replacement credential through the offline CLI, verify the new credential, then revoke the old one.
- **Principal/credential IDs were not captured by a shell script:** do not blindly rerun principal creation. First inspect the captured command output with token values redacted, or query the local database through an approved non-secret diagnostic. Duplicate principals make the audit trail harder to interpret.
- **Managed authentication returns 503:** verify managed mode, database availability and pepper format in both processes. Do not fall back to legacy mode to bypass a managed-auth failure.
- **Authentication returns 401:** verify that the correct token is used, the credential has not expired or been revoked, and the principal remains active.
- **Authorization returns 403:** verify the route's required scope. Do not solve a scope mismatch by granting every permission.
- **A token was exposed:** revoke that credential, issue a replacement and review audit/host exposure. Do not assume deleting a note or terminal scrollback invalidates the token.

## Known limitations

- Managed authentication is opt-in; legacy shared-key mode remains the default.
- Credential administration is offline CLI only; `credentials:manage` is reserved and does not provide HTTP credential-management endpoints.
- The pepper is a single configured secret; rotation invalidates existing credential verifiers.
- Environment variables reduce accidental command-line disclosure but are not a dedicated secret-management system.
- There is no human login, MFA, SSO/OIDC, tenant isolation or customer-facing role hierarchy.
- The offline administrator actor does not independently prove the OS user's identity.
- The two-person approval control is a prototype technical separation, not legal identity proof, organizational quorum or legal sign-off.
- Audit hash chaining is tamper-evident but not immutable against a privileged database administrator; external anchoring is not implemented.
- These controls do not establish production readiness or regulatory compliance.
