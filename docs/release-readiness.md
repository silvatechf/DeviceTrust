# Release Readiness and Public Showcase Criteria

## Current release posture

**Status: public repository, unreleased prototype; not production-ready.**

The repository is publicly visible, but no versioned release has been published and no license has been selected. Claims must be tied to code and validation evidence. Do not describe it as a production security platform, CRA conformity assessment, active device scanner or protective control.

A documented test or configured CI workflow is not proof that it passed on the current candidate. Record the exact commit SHA and observed workflow results before marking a validation gate complete.

## Public disclosure gates
- [x] README states implemented scope and major non-goals.
- [x] Threat model, prototype limitations and security controls are documented.
- [x] Security reporting policy is present.
- [x] Contribution guidance is present.
- [x] Changelog and reproducible local demo runbook are present.
- [x] Engineering decisions and test-to-control mapping are documented.
- [ ] Select and add an explicit open-source license, or clearly decide to retain all rights.
- [ ] Set an accurate repository description and relevant topics.
- [ ] Review the full Git history and confirm no secrets, private data, customer data or unintended material are present.
- [ ] Confirm branch protection / rulesets and required checks for the default branch.
- [ ] Resolve the unsigned commit history / signature policy before merging the current PR.
- [ ] Run the exact final candidate locally from a clean checkout and disposable database.
- [ ] Capture genuine desktop and mobile screenshots from the running application.
- [ ] Verify all console flows, API error paths and the /docs experience in a real browser.
- [ ] Confirm CI and CodeQL pass on the exact candidate commit.
- [ ] Publish a versioned release only after all required gates are satisfied.

## Demo acceptance gates
- [ ] Install dependencies from the documented development requirements in a clean environment.
- [ ] Pass Ruff, Bandit, pip-audit, Node syntax and pytest on the exact candidate commit.
- [ ] Start the API against a disposable SQLite database.
- [ ] Seed synthetic records and verify the documented walkthrough.
- [ ] Open the operator console at desktop and mobile widths.
- [ ] Connect using a local API key; confirm it is not persisted after refresh/disconnect.
- [ ] Verify inventory, posture, SBOM import, vulnerability triage, JSON report download and audit verification.
- [ ] Verify normalized evidence projection preserves raw values and handles invalid/unknown attributes.
- [ ] Confirm malformed and oversized SBOM requests are rejected.
- [ ] Confirm /docs remains usable and the console CSP is applied only to console/assets.
- [ ] Confirm no local database, credentials, environment files or generated artifacts are committed.

## Control-to-test evidence

The automated test inventory is maintained in Test Matrix. This mapping identifies test files; it does not claim that tests passed on the current branch head.

| Area | Automated evidence | Remaining validation |
|---|---|---|
| API authentication and fail-closed config | tests/test_api.py | Per-user authorization and key rotation are not implemented |
| Evidence input and verification boundary | tests/test_api.py | Source-specific identity and independent attestation |
| Normalization rules and projection | tests/test_evidence_normalization.py, tests/test_api.py | Stale/conflicting source behavior and expanded adapters |
| SBOM body limits and parsing | tests/test_sbom_input_limits.py, tests/test_sbom_validation.py | Full CycloneDX schema and ecosystem range semantics |
| Posture unknown/exposure behavior | tests/test_api.py, tests/test_posture_evidence_boundaries.py | Evidence-driven posture integration remains disabled |
| Audit integrity boundaries | tests/test_api.py, tests/test_audit_chain_boundaries.py | External checkpoint and concurrent chain-head serialization |
| Operator console headers and browser storage | tests/test_operator_console.py | Real-browser functional and responsive validation |
| CI quality gates | .github/workflows/ci.yml | Exact candidate workflow result must be checked |

## Production blockers
- Shared API key; no individual identity, RBAC, scopes, key rotation workflow or tenant isolation.
- The operator console receives the shared API key in browser memory. It is intended only for a trusted local operator workflow.
- No server-side browser session or backend-for-frontend.
- No documented database migration workflow; schema creation currently uses SQLAlchemy metadata.
- Audit hash chain has no independently retained checkpoint or immutable/WORM storage.
- CycloneDX support is a bounded subset, not complete schema or dependency-graph validation.
- Local advisories are synthetic; optional OSV lookup is best-effort and not comprehensive vulnerability coverage.
- Evidence normalization is initial and selected-attribute only; observations are not automatically associated or consumed by posture assessment.
- No rate limiting, concurrency quota or operational alerting.
- No demonstrated backup/restore, disaster recovery, deployment rollback or production TLS configuration.
- Container image scanning and PostgreSQL integration/restart tests remain to be completed.

## Claims suitable for a technical portfolio

Use only claims supported by the current code and exact validation evidence:
- Built a FastAPI modular-monolith prototype for IoT inventory and evidence-based security posture.
- Implemented bounded CycloneDX JSON ingestion and PURL-scoped synthetic advisory matching, with optional best-effort OSV lookup.
- Added justified vulnerability triage, JSON/Markdown reporting and SHA-256 hash-chain audit verification.
- Added bounded evidence ingestion and an initial read-only normalized projection for selected attributes.
- Integrated Ruff, Bandit, pip-audit, JavaScript syntax checks and pytest into GitHub Actions.
- Documented trust boundaries, threat scenarios, engineering trade-offs and residual risks.
- Added a local same-origin operator console that consumes the existing API.

Avoid claims that imply production readiness, complete CVE coverage, independent device attestation, CRA certification, immutable audit storage, multi-tenant security or attack prevention.

## Publication sequence
1. Complete review and merge only after human review, required CI and signature-policy resolution.
2. Validate the merged revision locally and record its exact commit SHA.
3. Select and add the license before inviting reuse or contributions.
4. Capture real screenshots using synthetic demo data only.
5. Update repository description/topics and publish a changelog-backed release.
6. Publish the portfolio / LinkedIn case study only after the final repository state and evidence are verified.