# Operator Console

DeviceTrust includes a lightweight same-origin operator console served by FastAPI at `/`. It consumes existing API routes and adds no frontend build chain.

## Local use

1. Start the API using the README quick-start instructions.
2. Open `http://127.0.0.1:8000/`.
3. Enter the local `DEVICETRUST_API_KEY`.
4. Disconnect when finished. The key is held only in page memory and is not persisted in browser storage.

The console supports inventory review, posture inspection, SBOM import, justified vulnerability triage, JSON report download and audit-chain verification. Triage requests use the existing API endpoint and are recorded by the backend audit service. API responses are rendered as text; security decisions remain server-side.

## Security boundary

This is a local operator interface for a single-trust-domain prototype. The shared API key is supplied to the browser and is visible to that browser session and its developer tools. Do not use this console with an internet-exposed instance or treat it as multi-user authentication. A production deployment requires server-side authenticated sessions or a backend-for-frontend, individual identity, authorization scopes, CSRF protection when cookie sessions are used, TLS, rate limiting and tenant isolation.

The page uses same-origin requests, does not persist credentials, avoids HTML string injection, and receives a restrictive Content Security Policy and baseline response security headers. These controls reduce browser attack surface but do not replace server-side authorization or a production security review.

## Known scope

- Overview values are derived from current inventory and vulnerability API responses.
- Device posture and findings are loaded from API endpoints.
- SBOM upload is limited in the browser to the server's 2 MiB limit.
- Audit verification reflects the current hash-chain guarantees and documented final-suffix deletion limitation.
- User management, RBAC, multi-tenancy and production session management are not implemented.
