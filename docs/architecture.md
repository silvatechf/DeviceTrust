# Architecture

## Current shape

DeviceTrust is a modular monolith with a FastAPI boundary, Pydantic input schemas, SQLAlchemy persistence and domain services for posture and SBOM analysis.

```text
Clients -> FastAPI routes -> Device registry / posture / SBOM / triage / audit
                                  |
                              SQLAlchemy
                                  |
                             SQLite / PostgreSQL
```

## Design decisions

- Keep one deployable application until scaling or isolation requirements justify separation.
- Keep domain decisions in services rather than route handlers.
- Treat missing evidence as `unverified`.
- Preserve advisory provenance with vulnerability results.
- Keep external intelligence integrations optional and bounded by timeouts.
- Avoid active probing or command execution against real IoT/OT devices in this prototype.

## Target modules

1. Device registry: identity, model, firmware, owner and lifecycle.
2. Exposure: network reachability evidence and management-plane interfaces.
3. Posture: evidence-backed capability assessment.
4. SBOM: CycloneDX ingestion and component normalization.
5. Vulnerability intelligence: OSV, NVD and CISA KEV correlation.
6. Events: authentication and operational change events.
7. Audit: provenance, integrity verification and external anchoring.
8. Reporting: operator-focused exposure and lifecycle reports.

SQLite is suitable for local development. PostgreSQL and Alembic migrations should be introduced before multi-user deployment. `create_all` is not a production migration strategy.
