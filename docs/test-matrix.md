# Test Matrix and Verification Evidence

This matrix connects security/product controls to concrete automated tests. It is a source map for review, not a statement that the tests passed on the current branch head.

## Automated control matrix

| Control / behavior | Test location | Evidence exercised | Known gap |
|---|---|---|---|
| Protected API routes require shared key | tests/test_api.py | Missing and invalid key; health remains public | No per-user identity, roles or tenant isolation |
| API fails closed without server key | tests/test_api.py | Unset DEVICETRUST_API_KEY returns 503 | No rotation/revocation workflow |
| Device input validation | tests/test_api.py | Duplicate IDs, traversal-like IDs and unknown fields | Fuzz/property-based coverage not established |
| Evidence ingestion boundary | tests/test_api.py | Source allowlist, bounded values, timezone, digest format, verification-state rejection | No independent source authentication |
| Evidence pagination | tests/test_api.py | Bounded limit/offset and stable ordered pages | No cursor pagination for large datasets |
| Evidence normalization rules | tests/test_evidence_normalization.py | Known, invalid, ambiguous, unknown and deterministic values; raw preservation | Limited attribute/source coverage |
| Normalized evidence API projection | tests/test_api.py | Authentication, canonical/raw values, unknown/invalid values and bounds | Stale/conflicting observations are not resolved |
| Posture uncertainty and exposure | tests/test_api.py, tests/test_posture_evidence_boundaries.py | Unknown remains unverified; exposed management interface remains high risk | Normalized observations do not feed posture |
| SBOM request size and JSON boundary | tests/test_sbom_input_limits.py | Malformed/non-object JSON and 2 MiB body cap | Deployment proxy limits need review |
| CycloneDX component validation | tests/test_sbom_validation.py | Component object/name, PURL validity, package identity and version matching | Not full schema/dependency graph validation |
| SBOM intelligence behavior | tests/test_sbom_osv_response.py, tests/test_sbom_validation.py | OSV response handling and deterministic synthetic feed | No complete CVE coverage or live-feed SLA |
| Audit chain integrity and writer serialization | tests/test_api.py, tests/test_audit_chain_boundaries.py, tests/test_postgres_persistence.py | Tampering, interior deletion, final-suffix limitation, concurrent complete `/products` API writes on SQLite/PostgreSQL with domain-to-audit ID pairing, injected post-audit-flush API failure with domain/audit rollback and subsequent lock reacquisition, direct concurrent writers, lock-row rollback and unauthenticated-write lock boundary | No external checkpoint or immutable store |\n| Audit-chain migration lifecycle | tests/test_migrations.py, tests/test_postgres_persistence.py | Upgrade from `0002_persistent_sbom`, verify singleton row and default version, downgrade to `0002` and verify table removal, then re-upgrade on disposable SQLite and PostgreSQL databases | Downgrade removes the lock state; coordinate application rollback and database migration, and retain an independent backup |
| Operator console security headers | tests/test_operator_console.py | CSP, nosniff, frame denial, no-store and static assets | No real-browser security suite |
| Console credential storage boundary | tests/test_operator_console.py | No localStorage/sessionStorage references in served script | No automated real-browser interaction suite |
| API documentation boundary | tests/test_operator_console.py | /docs remains available without console CSP header | Manual browser check required |

## CI quality gates

The current workflow at .github/workflows/ci.yml runs Node syntax check, dependency installation, Ruff, Bandit, pip-audit and pytest. CodeQL is configured separately in .github/workflows/codeql.yml.

A configured workflow is not a successful workflow. Before release, inspect the exact candidate commit's workflow runs, job conclusions and CodeQL status. Record the candidate SHA and date in the release evidence.

## Manual / integration verification not yet evidenced
- Clean-checkout setup on supported Windows and Linux environments.
- Docker Compose PostgreSQL startup, restart persistence and failure behavior.
- Real-browser desktop and mobile console walkthrough.
- SBOM upload, triage and report download using seeded synthetic data.
- Audit lock contention under sustained load and external writers that bypass the application.\n- Production migration rollback and application/database version coordination; automated downgrade coverage uses isolated disposable databases only.
- Backup/restore and deployment rollback.
- Secret scanning and full Git-history review.
- Branch protection / ruleset and commit-signature policy verification.

## Adding a new control
1. Identify the threat or failure mode in the threat model.
2. Define expected secure and failure behavior.
3. Add a focused test at the lowest practical layer and an API-level test where the boundary matters.
4. Link the test here and in security-controls.md.
5. Record residual limitations; do not infer production assurance from a passing unit test.
