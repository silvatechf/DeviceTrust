# Security Controls

This document describes what the current code does, where to find its tests and what each control does not guarantee.

## Controls and limits

| Area | Current implementation | Test location | Limitation |
|---|---|---|---|
| API authentication | Shared key, constant-time comparison; missing server key fails closed | `tests/test_api.py` | No individual identity, scopes, RBAC, tenant isolation or rotation workflow |
| Input validation | Pydantic schemas, strict extra-field handling and bounded fields | `tests/test_api.py` | No global rate limit or API gateway quota |
| Evidence ingestion | Source allowlist, bounded values, timezone-aware timestamps and digest format checks | `tests/test_api.py` | No source-specific identity or independent attestation |
| Verification boundary | Server assigns `unverified`; client cannot self-verify | `tests/test_api.py` | No operator review workflow |
| SBOM body | Streaming 2 MiB limit; malformed/non-object JSON rejected | `tests/test_sbom_input_limits.py` | Reverse-proxy limits not validated |
| SBOM components | CycloneDX JSON `specVersion` 1.5 allow-list, component count/field bounds and PURL validation | `tests/test_sbom_validation.py` | Only version declaration is gated; not full CycloneDX schema or dependency-graph validation |
| Product SBOM comparison | Authenticated, read-only comparison restricted to two accepted imports of the requested product release; duplicate and missing PURLs are not guessed | `tests/test_product_sbom_diff.py` | Exact PURL identity does not prove supplier/component equivalence; comparison does not re-evaluate vulnerabilities |
| Local advisory matching | PURL package type/name and version-before-fixed comparison | `tests/test_sbom_validation.py` | Synthetic demo records, not a maintained feed |
| OSV lookup | Optional exact PURL/version query | `tests/test_sbom_osv_response.py` | Best-effort; errors are skipped and coverage is not guaranteed |
| Posture assessment | Missing data stays unverified; declared exposed management interface is high risk | `tests/test_posture_evidence_boundaries.py` | Uses declared metadata, not active discovery |
| Audit | SHA-256 hash chain and verification endpoint | `tests/test_audit_chain_boundaries.py` | No external checkpoint, immutable store or concurrent writer serialization |
| Console | Same-origin assets, CSP and baseline response headers | `tests/test_operator_console.py` | No real-browser security suite |

## Evidence handling

- Allowed sources are `manual`, `router_import`, `network_observation`, `sbom`, `firmware` and `vendor_api`.
- Source observation time and server recording time are stored separately.
- Confidence is descriptive metadata, not a probability or verification state.
- The server assigns `unverified`.
- Observations may remain unassigned.
- References are opaque; the API does not fetch them.
- A supplied SHA-256 digest does not prove who created the artifact.
- Audit payloads omit the raw observation value.

Evidence observations are not yet used for device matching, conflict resolution or posture calculations.

## Posture and internet exposure

The posture service evaluates declared security-profile fields. Unknown values remain unknown. An internet-exposed device or management interface is reported as high risk, but the application does not independently test reachability.

## SBOM boundary

CycloneDX parsing is a bounded subset. Components without PURLs are retained but cannot be matched by the local demo feed. Synthetic `DT-DEMO-*` advisories support deterministic demonstrations only. OSV lookup may be unavailable or incomplete; no result must not be interpreted as proof that a component is vulnerability-free.

## Lifecycle data

The current persistence model stores `support_until` on a device. It does not yet implement a full lifecycle model with independent support status, end-of-life announcement and source provenance. Do not describe those fields as implemented.

## Audit guarantees

The hash chain can detect modification of retained entries and gaps when a later retained entry references a missing predecessor. It cannot detect deletion of the final entry or suffix without an independently retained checkpoint. A privileged attacker able to rewrite the database can recompute the chain. Multi-worker concurrent writes need a serialized chain-head mechanism.

## Before production use

Add individual identity and authorization, key lifecycle, rate limiting, migration management, independent audit anchoring, retention policy, concurrency controls, PostgreSQL integration tests, operational monitoring and a documented deployment model. See [Threat model](threat-model.md) and [Release readiness](release-readiness.md).
