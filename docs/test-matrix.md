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
| CycloneDX component validation | tests/test_sbom_validation.py | CycloneDX JSON `specVersion` allow-list (1.5), component shape/name/version, PURL syntax and version consistency, package identity and version-before-fixed matching | Bounded parser; not full CycloneDX schema or dependency-graph validation |
| SBOM intelligence behavior | tests/test_sbom_osv_response.py, tests/test_sbom_validation.py | Malformed OSV payload/entry handling and severity normalization; deterministic synthetic package/advisory matching | No complete CVE coverage or live-feed SLA |
| Product/release SBOM API boundary | tests/test_api.py | Authenticated product and release creation, import/list/component/finding route authentication, missing/invalid key rejection | Shared API key only; no per-user identity, roles or tenant isolation |
| Product SBOM import persistence and idempotency | tests/test_api.py, tests/test_sbom_persistence_models.py | Accepted import metadata and component occurrences persist; exact-byte digest idempotency on same release/format; uniqueness constraints on import digest and import-local component ordinal | Raw SBOM documents are not retained; no global component identity or cross-import deduplication |
| Product SBOM validation and rejection | tests/test_api.py, tests/test_sbom_input_limits.py, tests/test_sbom_validation.py | Invalid documents are rejected without accepted-import persistence; malformed/non-object JSON and oversized bodies are rejected; bounded CycloneDX 1.5 and PURL rules are enforced | Not full CycloneDX schema or dependency-graph validation |
| Product SBOM changed-content and release isolation | tests/test_api.py | Changed request bytes create a new import with digest over exact bytes; identical bytes imported to distinct releases remain release-scoped | No cross-product relationship inference or cross-import component deduplication |
| Product SBOM component/finding provenance | tests/test_api.py, tests/test_sbom_persistence_models.py | Import-local component ordinals; original component name/version retained; findings returned only for the exact component occurrence | No global component identity or external provenance attestation |
| Product SBOM transaction atomicity | tests/test_api.py, tests/test_postgres_persistence.py | Injected audit-append failure rolls back product SBOM import rows on SQLite and PostgreSQL; failed product API writes roll back domain/audit state and release the lock | Sustained contention/load behavior remains unmeasured |
| Product SBOM PostgreSQL persistence | tests/test_postgres_persistence.py | Product/release/import/component/finding records survive engine disposal; import rollback on audit failure; concurrent API writes preserve domain/audit atomicity | CI PostgreSQL coverage is automated integration evidence, not production operational validation |
| Product SBOM comparison | tests/test_product_sbom_diff.py | Equivalent content/order independence, add/remove and reverse direction, simultaneous version/name changes, qualifier/subpath identity boundaries, duplicate ambiguity, unidentified and invalid legacy PURLs, self-comparison, read-only persistence/audit, authentication and release boundaries | PURL identity is not artifact equivalence; no vulnerability re-evaluation |
| Versioned product SBOM reassessment (proposed in PR #45) | tests/test_sbom_reassessment.py, tests/test_postgres_persistence.py | Append-only assessment history; idempotency and configuration mismatch; concurrent same-key requests; component-scoped findings; legacy triage isolation; malformed scanner-output rollback; PostgreSQL persistence | Exact-head CI/CodeQL must pass before treating these tests as validated; OSV remains best-effort; shared API key is not individual operator identity; no KEV/EPSS or human-reviewed decisions |
| KEV/EPSS provider validation (proposed in stacked PR) | tests/test_intelligence.py, tests/test_sbom_reassessment.py, tests/test_postgres_persistence.py | CISA catalog envelope/entry validation; FIRST score/percentile/date validation; unrequested CVE rejection; explicit disabled, unavailable, not-found and not-applicable states; per-finding snapshot persistence | Provider network behavior still requires exact-head CI and controlled live-feed smoke evidence; source data does not prove product applicability |
| Audit-chain integrity and application-writer serialization | tests/test_api.py, tests/test_audit_chain_boundaries.py, tests/test_postgres_persistence.py | Retained-entry tampering, interior deletion and final-suffix limitation; concurrent complete API writes on SQLite/PostgreSQL with domain/audit pairing; direct concurrent writers; transactional rollback and lock reacquisition; unauthenticated writes do not acquire the audit lock | No independent external checkpoint or immutable/WORM store; privileged DB administrators and external writers remain trusted |
| Audit-chain migration lifecycle | tests/test_migrations.py, tests/test_postgres_persistence.py | Upgrade from `0002_persistent_sbom`, verify singleton state row/default version, downgrade to `0002` and verify table removal, then re-upgrade on disposable SQLite and PostgreSQL databases | Downgrade removes the lock state; production rollback requires coordinated application/database rollback and a preserved backup |
| Operator console security headers | tests/test_operator_console.py | CSP, nosniff, frame denial, no-store and static assets | No real-browser security suite |
| Console credential storage boundary | tests/test_operator_console.py | No localStorage/sessionStorage references in served script | No automated real-browser interaction suite |
| API documentation boundary | tests/test_operator_console.py | /docs remains available without console CSP header | Manual browser check required |
| Docker Compose CI smoke and recovery | scripts/ci-compose-smoke.sh, .github/workflows/ci.yml | Disposable CI stack startup/migrations, API authentication, seed fail-closed behavior, product SBOM import/listing across API restart, DB restart and audit verification; `pg_dump`/restore to a separate DB followed by restored audit-chain and SBOM audit-event verification | CI-only smoke; does not validate developer Windows/Linux environments, backup retention, off-host storage, RPO/RTO or production rollback |
| Full-history secret scanning (CI evidence) | .github/workflows/ci.yml | CI configures full-depth checkout, `--all --full-history`, checksum verification of the Gitleaks v8.30.1 release archive, and redacted findings | Workflow configuration is not proof of a successful scan; detection is pattern-based. Manually review private/customer data and Gitleaks findings; no allowlist is configured |

## CI quality gates

The CI workflow configures separate quality, PostgreSQL integration, disposable Compose smoke/recovery and full-history Gitleaks jobs, with read-only contents permissions and bounded job timeouts. The quality job configures Node syntax validation, pre-commit configuration validation and hook-environment installation, Ruff, Bandit, runtime/development dependency audits and pytest. The PostgreSQL job runs `tests/test_postgres_persistence.py`; the Compose job runs `scripts/ci-compose-smoke.sh`; the secret-history job verifies the official Gitleaks v8.30.1 archive checksum before scanning reachable Git history with redacted findings. CodeQL is configured separately in `.github/workflows/codeql.yml`. These are workflow definitions; inspect exact-head run/job conclusions before treating any CI evidence as completed.

A configured workflow is not a successful workflow. Before release, inspect the exact candidate commit's workflow runs, job conclusions and CodeQL status. Record the candidate SHA and date in the release evidence.

The `compose-smoke` job is an automated disposable-runner check, not a developer-environment or production recovery exercise. It verifies startup/migrations, seed fail-closed behavior, product SBOM persistence across API/DB restarts, audit-chain verification and PostgreSQL backup/restore into a separate disposable database.

## Manual / integration verification not yet evidenced
- Clean-checkout setup on supported Windows and Linux environments.
- Local Docker Compose startup on supported developer environments; CI now covers PostgreSQL startup, restart persistence, fail-closed seeding and backup/restore.
- Real-browser desktop and mobile console walkthrough.
- Real-browser end-to-end SBOM upload, triage and report-download walkthrough using seeded synthetic data (API and CI Compose checks are not browser validation).
- Sustained audit-lock contention/load testing and behavior of external database writers that bypass the application.
- Production migration rollback and application/database version coordination; automated downgrade coverage uses isolated disposable databases only.
- Backup retention, off-host storage, defined RPO/RTO and production rollback procedures.
- Manual review of private/customer data and triage of Gitleaks findings; configured pattern-based scanning does not prove complete secret detection.
- Branch protection / ruleset and commit-signature policy verification.

## Adding a new control
1. Identify the threat or failure mode in the threat model.
2. Define expected secure and failure behavior.
3. Add a focused test at the lowest practical layer and an API-level test where the boundary matters.
4. Link the test here and in security-controls.md.
5. Record residual limitations; do not infer production assurance from a passing unit test.
