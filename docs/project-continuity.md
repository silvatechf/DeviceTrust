# Project Continuity Record

**Last reconciled:** 2026-11-13  
**Repository:** `silvatechf/DeviceTrust`  
**Authoritative branch:** `main`  
**Purpose:** recover the project's verified state after a chat, session or contributor handoff.

This document is an operational index, not a replacement for source code, pull-request history, architecture documents or architecture decision records (ADRs). When this record conflicts with GitHub, the current repository state and merged history take precedence. Update this document when a material milestone is merged or the next delivery changes.

## 1. Product and scope

DeviceTrust is an early-stage Python/FastAPI prototype for product-security intelligence and evidence management for connected and embedded products. The initial customer hypothesis is small and medium-sized manufacturers; consultancies and specialist integrators are complementary users.

The prototype connects product/release context, declared SBOM data, vulnerability intelligence, attributable human decisions and traceable evidence. It is not production-ready and does not establish CRA compliance, perform conformity assessments, independently attest product contents, detect intrusions or prevent attacks.

See:
- [README](../README.md) — public product and capability summary.
- [Product vision](product-vision.md) — product direction, target users, principles and delivery phase gates.
- [Market positioning](market-positioning.md) — target users, buyer hypotheses and claims boundaries.
- [Architecture](architecture.md) — modules, data flow and trust boundaries.
- [Prototype limitations](prototype-limitations.md) — claims that must not be made.
- [Threat model](threat-model.md) — assets, abuse cases and residual risks.
- [Release readiness](release-readiness.md) — evidence required before a release.

## 2. Verified repository baseline

At the time this record was reconciled:

- Default branch: `main`.
- Latest verified main commit at this reconciliation: `1e37a2e76f20e949faa5c7d7b109390cc39ad825` (PR #85 merge commit, 2026-11-13).
- PR #85, `Fix Product SBOM applicability rendering`, is merged; its branch CI and post-merge CI and CodeQL completed successfully. The Product SBOM console now renders structured applicability metadata instead of coercing objects to `[object Object]`.
- PR #74, `docs: add project continuity and handoff record`, was merged on 2026-11-10.
- PR #77, `feat(cli): add authenticated CycloneDX SBOM import`, was merged on 2026-11-10; exact-head CI and CodeQL both completed successfully. Merge commit: `2f210663ab5e424795d4884e5febf8e398d09a1f`.
- PR #80, `test: cover complete product SBOM review and VEX workflow`, was merged on 2026-11-10. Exact-head CI and CodeQL passed for head `3075e71e01ef259cb7894b66c13e716752ccef4f`; merge commit: `825e008312eca5fb16ffc64b3f4321bdd90b7da6`. The integration test exercises the product/release API, authenticated CLI import/assessment/history/findings, evidence, decision, manifest, author signature, independent approval, VEX export and audit history using synthetic fixtures and stubbed external enrichment.
- PR #75 was closed as superseded by PR #77.
- PR #73 added an API-level end-to-end test for evidence artifact upload, revision-bound evidence manifest, author Ed25519 signature, independent second-person approval and deterministic CycloneDX 1.5 VEX export.
- PR #74 added this continuity record and its README link; its exact-head checks passed before merge.
- PR #72 implemented the conservative CycloneDX 1.5 VEX export slice and is already part of main.
- PR #68 implemented resumable, idempotent release-wide reassessment.
- PR #71 documented the VEX export contract in DEC-013.

These statements describe the observed state at the reconciliation point. Always query GitHub again before relying on branch heads, PR state or check conclusions for a new change.

## 3. Implemented capability map

The following capabilities are documented as implemented in the current prototype:

- FastAPI modular monolith with Pydantic and SQLAlchemy persistence.
- Alembic migrations; SQLite and PostgreSQL paths with automated integration coverage.
- Device inventory and declared posture, preserving unknown states.
- Bounded evidence observations and artifact storage with server-computed SHA-256 integrity checks.
- Bounded CycloneDX JSON 1.5 SBOM import, product/release association and component occurrence persistence.
- SBOM comparison and conservative PURL identity handling.
- Versioned, append-only SBOM assessment runs; import-level and release-wide reassessment with idempotency.
- Optional OSV lookup and CISA KEV / FIRST EPSS enrichment with provenance and explicit coverage states.
- Conservative PyPI version comparison using PEP 440; unsupported ecosystems remain unknown.
- Attributable append-only vulnerability review decisions.
- Operator-controlled Ed25519 signatures bound to exact decision revisions.
- Independent second-person approval.
- Immutable evidence manifests bound to decision revisions and signature/approval envelope v2.
- Conservative CycloneDX 1.5 VEX export under DEC-013, with fail-closed eligibility and schema validation.
- Authenticated CLI client for CycloneDX import, assessment, history and findings; import is a thin API client with a bounded 2 MiB file read and redirect following disabled.
- Automated integrated API/CLI test for the product SBOM review-to-VEX path, including fail-closed manifest gating, signature, independent approval and audit verification (PR #80).
- Managed API principals and scoped credentials, while legacy shared-key mode remains backwards-compatible default.
- Audit hash-chain verification and transactional serialization of concurrent writers.

For endpoint details and exact limitations, use the README and relevant implementation/decision documents rather than duplicating API contracts here.

## 4. Current workstream and next delivery

**Workstream:** deliver a coherent operator-facing product/release SBOM vertical slice (see [Product Vision](product-vision.md) and [Roadmap](roadmap.md)).

**Latest merged increment:** PR #85 (`Fix Product SBOM applicability rendering`) is merged into `main` at `1e37a2e76f20e949faa5c7d7b109390cc39ad825`; branch CI and post-merge CI/CodeQL succeeded. PR #86 (`Add Product SBOM human review controls`) is open on `feat/product-sbom-review-console`; its CI and CodeQL are pending. The PR adds a first browser interface for attributable decisions and decision history; it does not yet expose evidence artifact handling, signatures, independent approval or VEX export.

A manual local validation was reported on 2026-11-13 against the merged `main` Console and a localhost-only API. The operator connected successfully, loaded the existing product-release import, inspected assessment history (#1 and #2), and viewed three synthetic findings with structured applicability details. The audit endpoint returned `valid: true` with 12 entries. This is user-reported browser/API evidence, not a CI run or production validation. The local run did not exercise managed-mode human review, evidence artifact upload, decision manifests, signatures, independent approval, VEX export or external intelligence enrichment.

**Current delivery:** complete the operator-facing product/release SBOM governance workflow in focused increments. PR #86 begins with attributable human-review submission and decision history. Preserve the API as the authorization and domain boundary; do not duplicate parsing, persistence, signing policy or decision logic in JavaScript. Keep the legacy device-scoped workflow clearly separated.

Why this order:
- The existing CLI exposes `assess`, `history` and `findings`, but expects an existing `import_id`.
- A pipeline integration that requires users to pre-create an import outside the pipeline is not a complete SBOM-to-assessment workflow.
- Import, authorization and parsing must remain owned by the API; the CLI must not open the database or duplicate parser/business logic.
- The future Action must not silently turn every finding into a failed build. Policy thresholds and incomplete intelligence need explicit semantics.

### Acceptance criteria for CLI import

1. Use the existing authenticated API and the same authorization boundary as other CLI operations.
2. Accept a local CycloneDX JSON file without logging or printing its contents.
3. Enforce a documented size bound before upload; the API remains authoritative for format/schema validation.
4. Use a safe, explicit content type and avoid following redirects with credentials.
5. Return stable JSON and preserve the existing documented exit-code contract.
6. Distinguish configuration, network, authentication, API validation/conflict and server errors.
7. Test successful import, invalid/nonexistent file, oversized input, auth rejection, API rejection, timeout/network failure and idempotent retry behavior.
8. Do not place API tokens in command-line arguments, URLs, output or logs; read the token from the established environment variable or a safer supported credential mechanism.
9. Update CLI help, README, test matrix and roadmap only when behavior is implemented and validated.

CLI import is merged and the manual API/CLI walkthrough has now been exercised locally with a disposable database. The next scope is the operator-facing product/release vertical slice; a composed CLI command and GitHub Action should be considered only after the operator workflow and policy semantics are clear.

## 5. Security and architecture invariants

- Keep the modular-monolith/API boundary; do not add microservices without a demonstrated need.
- The CLI and future Action are API clients. They must not access the database directly or reimplement domain logic.
- Preserve least privilege and managed credential scopes. Never expose credentials in logs, output, process arguments or committed workflow files.
- Treat SBOMs, evidence, provider intelligence and user-supplied metadata as untrusted input.
- Preserve provenance, timestamps, source and uncertainty. Missing intelligence must never mean no risk.
- Do not infer product identity, supplier, PURL, affected versions or VEX conclusions without source evidence.
- VEX export remains conservative, attributable, approved and revision-bound; it is not a legal attestation or external publication.
- Audit hash chaining is tamper-evident, not immutable against a privileged database administrator. External anchoring remains unimplemented.
- Do not claim CRA compliance, conformity assessment, independent attestation or production readiness.

## 6. Known limitations and deferred work

- No human login, MFA/SSO or tenant isolation.
- Legacy shared-key authentication remains the backwards-compatible default; migration to managed credentials is not complete.
- No external audit checkpoint/anchoring or independent WORM storage.
- Evidence byte integrity does not prove source authenticity or truth.
- No malware scanning or evidence-signature verification policy.
- SBOM ecosystem/version semantics remain limited; native Debian, RPM, npm, Maven and Go semantics, vendor backports and source/binary relationships remain open.
- No automated reassessment scheduling or feed-change triggers.
- No general-purpose VEX authoring, OpenVEX support or external VEX publication.
- No automatic CRA legal timer or ENISA submission.
- Backup/restore, deployment rollback and legacy database adoption still require operational evidence before a versioned release.

Use [Roadmap](roadmap.md), [Identity and Access Governance](identity-access-governance.md), [Security Controls](security-controls.md) and [Release Readiness](release-readiness.md) for the detailed status.

## 7. Delivery protocol

For each material increment:

1. Reconcile current `main`, open PRs, relevant issues, existing implementation and documentation.
2. State the smallest valuable scope and acceptance criteria.
3. Create a focused branch from the current verified base; do not work directly on protected/default branches.
4. Reuse existing services, schemas, fixtures and test helpers where appropriate; avoid parallel implementations.
5. Add or update tests and documentation in the same change.
6. Run relevant local checks when available; otherwise report that CI is the validation source.
7. Open a focused PR with scope, security implications, limitations and exact validation evidence.
8. Inspect checks on the exact PR head; fix observed failures rather than making speculative refactors.
9. Merge only with explicit authorization.
10. After merge, verify the main commit and update this record with the new baseline and next workstream.

Never report a task as complete merely because code was authored. Use these states consistently:

- `PLANNED` — scoped, not implemented.
- `IN_PROGRESS` — active branch/work exists.
- `IMPLEMENTED` — code or documentation exists, validation not yet complete.
- `VALIDATED` — required checks passed on the exact candidate commit.
- `MERGED` — integrated into the authoritative branch and verified.

## 8. Handoff checklist

At the beginning of a resumed session or new chat:

- [ ] Read this continuity record and README.
- [ ] Fetch the current `main` SHA; do not assume the recorded SHA is still current.
- [ ] Inspect open PRs and relevant issues; distinguish drafts, active work and stale proposals.
- [ ] Inspect the branch and exact commit associated with the active workstream.
- [ ] Check CI conclusions for the exact current PR head.
- [ ] Compare actual code/docs against this record; correct stale statements before proceeding.
- [ ] Continue from the next incomplete acceptance criterion; do not recreate already merged work.

At the end of a material delivery, update the baseline, PR/commit evidence, status and next action in this file.


## 9. Verified manual product SBOM walkthrough — 2026-11-13

This execution was performed locally against the current `main` baseline (`d8587e0`) using the existing API and CLI, not a direct database write from the CLI.

- Database: disposable SQLite file under the operating-system temporary directory; no production/shared database was used.
- API: localhost-only process on port 8766; stopped after verification.
- Authentication: temporary local legacy API key, removed from the PowerShell process environment after the run; no key was recorded in the repository or evidence summary.
- Records created: product ID `1`, release ID `1`, SBOM import ID `1`, assessment ID `1` within that disposable database only.
- Audit verification: `GET /audit/verify` returned `valid: true` and `entries: 4`; `GET /audit` returned four events.
- Preserved artifacts: temporary SQLite database and API stdout/stderr logs outside the repository.
- Not covered: browser console, external OSV/KEV/EPSS enrichment, human decision/signature/approval, VEX export, production deployment or backup recovery.

This is a manually observed local demonstration, not a substitute for automated tests, independent security review or production-readiness evidence. The exact procedure and limitations are recorded in [Local Demonstration Runbook](demo-runbook.md).
