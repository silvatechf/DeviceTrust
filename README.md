# DeviceTrust

**Product Security Intelligence & Evidence Management — an early-stage Python platform prototype for connected and embedded products.**

[![CI](https://github.com/silvatechf/DeviceTrust/actions/workflows/ci.yml/badge.svg)](https://github.com/silvatechf/DeviceTrust/actions/workflows/ci.yml)
[![CodeQL](https://github.com/silvatechf/DeviceTrust/actions/workflows/codeql.yml/badge.svg)](https://github.com/silvatechf/DeviceTrust/actions/workflows/codeql.yml)

DeviceTrust explores how teams can organise product and asset records, analyse supported software-component inventories, assess vulnerability information, document security decisions and retain traceable evidence across connected and embedded products.

The **initial customer hypothesis** is small and medium-sized **manufacturers of products with digital elements**, such as industrial gateways, sensors and embedded controllers. Product-security consultancies and specialist integrators are complementary users and potential channels. Food production and cold-chain infrastructure remain the synthetic demonstration context, not the limit of the product concept.

> **Current status:** early-stage Python/FastAPI prototype for local technical evaluation. DeviceTrust does not establish CRA compliance, perform conformity assessments, submit regulatory notifications, independently attest product contents, discover devices on networks, detect intrusions or prevent attacks.

## Product direction

The intended workflow is to connect:

1. Product, asset and version context.
2. Software-component inventories and their provenance.
3. Vulnerability intelligence and affected-version assessment.
4. Reviewed security decisions, including future VEX support.
5. Evidence, audit history and exportable assessment records.

This direction is relevant to product-security workflows under the EU Cyber Resilience Act (CRA), but DeviceTrust currently supports only a small subset of the underlying engineering activities. CRA obligations extend beyond SBOMs and vulnerability triage. Legal applicability and manufacturer responsibilities must be assessed for each product and organisation.

See [Market Positioning](docs/market-positioning.md) for target users, buyer hypotheses, regulatory boundaries, market validation and the claims policy.

## The current prototype

The application is built with Python, FastAPI, Pydantic and SQLAlchemy. It is a modular monolith intended for local evaluation and technical learning.

Implemented prototype workflows:

1. Store device inventory and declared security attributes.
2. Assess declared profiles and keep missing information as `unverified`.
3. Accept bounded evidence observations while preserving source and timestamps.
4. Parse a supported subset of CycloneDX JSON and match components against synthetic demo advisories; optionally query OSV.
5. Record vulnerability-triage decisions with a mandatory justification.
6. Generate JSON/Markdown reports and verify a SHA-256-linked audit history.
7. Persist accepted product-release SBOM imports, component occurrences and product-scoped findings through the authenticated product SBOM API (feature branch; validation pending).\n8. Use a same-origin local operator console.

Evidence observations are currently stored separately from posture inputs. Ingestion does not prove a claim, identify a product or device, or change its posture result. The legacy device-scoped SBOM workflow remains available. The new product-scoped SBOM persistence flow is implemented on the current feature branch but is not yet merged or operationally validated.

### Product-scoped SBOM API (feature branch)

The persistent SBOM work introduces these authenticated endpoints:

- `POST /products` — create a declared product identity.
- `POST /products/{product_id}/releases` — create a product release.
- `POST /product-releases/{release_id}/sbom` — import a bounded CycloneDX JSON 1.5 document.
- `GET /product-releases/{release_id}/sbom` — list accepted imports.
- `GET /sbom/imports/{import_id}/components` — list immutable component occurrences.
- `GET /sbom/components/{component_id}/findings` — list findings tied to a component occurrence.

The import digest is calculated from the exact request bytes. A repeated digest for the same release and format returns the existing import. Only fully validated imports are persisted. The API does not store raw SBOM documents or infer a relationship between a product and a device.

This API is under review in [PR #22](https://github.com/silvatechf/DeviceTrust/pull/22). Its CI, migration and PostgreSQL behavior must be verified before treating it as a released capability.

## What is not implemented

- Product and release-version domain model with persistent SBOM history.
- Persistent component inventory, SBOM diffing or product-to-component traceability.
- SPDX ingestion or CycloneDX VEX generation.
- KEV/EPSS enrichment and contextual product-version assessment.
- Individual operator accounts, RBAC, tenant isolation or production browser sessions.
- Automated CRA reporting, ENISA Single Reporting Platform integration or conformity assessment.
- Active LAN discovery, packet capture, device agents or independent firmware/hardware attestation.
- Immutable/WORM audit storage, external audit checkpoints or multi-writer serialization.
- Production operations, real-time intrusion detection, incident-response automation or attack prevention.

See [Prototype limitations](docs/prototype-limitations.md), [Threat model](docs/threat-model.md) and [Release readiness](docs/release-readiness.md).

## Architecture at a glance

DeviceTrust is a **modular monolith**, not a set of microservices. FastAPI handles HTTP requests and authentication; route handlers coordinate domain logic; SQLAlchemy persists devices, evidence, vulnerabilities and audit events.

```mermaid
flowchart LR
    CLIENT[API client / local console] --> API[FastAPI]
    API --> AUTH[Shared API key]
    AUTH --> ROUTES[Route handlers]
    ROUTES --> POSTURE[Posture service]
    ROUTES --> EVIDENCE[Evidence + normalizer]
    ROUTES --> SBOM[SBOM + advisory lookup]
    ROUTES --> TRIAGE[Vulnerability triage]
    ROUTES --> REPORT[Reports]
    ROUTES --> AUDIT[Audit service]
    POSTURE --> DB[(SQLAlchemy / SQLite or PostgreSQL)]
    EVIDENCE --> DB
    SBOM --> DB
    TRIAGE --> DB
    AUDIT --> DB
```

The diagram shows the current application structure, not a deployment topology. See [Architecture](docs/architecture.md) for request flow and trust boundaries.

## Run locally

### 1. Create a virtual environment

**Windows PowerShell**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
$env:DEVICETRUST_API_KEY = "replace-with-a-random-local-secret"
```

**macOS / Linux**
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
export DEVICETRUST_API_KEY="replace-with-a-random-local-secret"
```

Keep this key local. Do not commit it or reuse a production credential.

### 2. Apply migrations and start the API

```bash
alembic upgrade head
uvicorn app.main:app --reload
```

Schema changes are managed through Alembic. The application does not create or modify database tables at startup. Run `alembic upgrade head` after installing dependencies and whenever a new migration is introduced.

- Operator console: http://127.0.0.1:8000/
- Interactive API documentation: http://127.0.0.1:8000/docs

The console receives the shared API key in browser memory. Use it only with a trusted local instance. Do not expose the service or key to the public internet.

### 3. Load synthetic demo data (optional)

Use a dedicated disposable SQLite file for the demonstration. Do not point the demo seeder at a database containing data you need to preserve.

**Windows PowerShell** (run these commands in the same terminal session):
```powershell
$env:DATABASE_URL = "sqlite:///devicetrust-demo.db"
python -m app.seed
uvicorn app.main:app --reload
```

**macOS / Linux**:
```bash
export DATABASE_URL="sqlite:///devicetrust-demo.db"
python -m app.seed
uvicorn app.main:app --reload
```

The seeder creates three synthetic devices and imports the sample CycloneDX document for `EDGE-GW-003`. It does not reset an existing database. See the [Demo runbook](docs/demo-runbook.md).

## Optional PostgreSQL setup

Copy `.env.example` to `.env`, replace both placeholders with independent random secrets, then run:

```bash
docker compose up --build
```

The container applies Alembic migrations before starting the API. The API port is bound to localhost. Keep `.env` private and never commit it. PostgreSQL integration and restart persistence are exercised in CI; backup/restore and operational recovery still require manual verification.

## Run quality checks

```bash
ruff check .
bandit -q -r app
pip-audit -r requirements.txt
node --check web/app.js
pytest -q
```

GitHub Actions runs the configured checks on pushes and pull requests; CodeQL is configured separately. Check the exact commit's workflow results before claiming they passed. Tests and static analysis provide useful evidence, not proof that the application is secure or production-ready. The [test matrix](docs/test-matrix.md) maps controls to test locations and records remaining gaps.

## Security principles

- Missing information stays unknown; it is not treated as safe.
- Submitted product, device and evidence claims are not independent attestation.
- Weak identifiers such as MAC, IP and hostname are not identity proof.
- Vulnerability triage requires a written justification.
- KEV presence and EPSS scores are intelligence signals, not automatic CRA reporting triggers.
- VEX statements require product-version context, evidence and reviewed justification.
- Audit hash chaining provides tamper evidence, not immutable storage.
- External intelligence failures or missing results do not mean that a component is vulnerability-free.
- DeviceTrust is an assessment and evidence-management prototype, not an inline IDS/IPS or product conformity assessor.

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Contributions should follow [CONTRIBUTING.md](CONTRIBUTING.md).

## Technical documentation

| Document | What it helps explain |
|---|---|
| [Market positioning](docs/market-positioning.md) | Target market, CRA context, buyer hypotheses and claims policy |
| [Architecture](docs/architecture.md) | Request flow, modules, data flow and trust boundaries |
| [Engineering decisions](docs/engineering-decisions.md) | Why the current design was chosen and its trade-offs |
| [Security controls](docs/security-controls.md) | Implemented controls, tests and limitations |
| [Threat model](docs/threat-model.md) | Assets, trust boundaries, abuse cases and residual risks |
| [Evidence ingestion](docs/evidence-ingestion.md) | Evidence API behavior and validation boundaries |
| [Evidence normalization](docs/evidence-normalization.md) | Canonical attributes, normalization and future association |
| [Operator console](docs/operator-console.md) | Browser workflow and credential boundary |
| [Demo runbook](docs/demo-runbook.md) | Repeatable local walkthrough with synthetic data |
| [Prototype limitations](docs/prototype-limitations.md) | What must not be claimed |
| [Test matrix](docs/test-matrix.md) | Control-to-test mapping and manual verification gaps |
| [Release readiness](docs/release-readiness.md) | Evidence required before a release |
| [Roadmap](docs/roadmap.md) | Implemented work and next steps |
| [Interview guide](docs/interview-guide.md) | A clear way to explain the project and defend decisions |
| [Changelog](CHANGELOG.md) | Development history |

## References

- Regulation (EU) 2024/2847 — Cyber Resilience Act.
- European Commission — Cyber Resilience Act implementation and reporting obligations.
- ENISA — CRA Single Reporting Platform.
- CycloneDX — Software Bill of Materials (SBOM) and Vulnerability Exploitability eXchange (VEX).
- SPDX — Software component and supply-chain data exchange.
- CISA Known Exploited Vulnerabilities (KEV) Catalog.
- FIRST — Exploit Prediction Scoring System (EPSS).
- OSV — Open Source Vulnerabilities database and API.

## License

No license has been selected. Until one is added, all rights are reserved. See the release-readiness checklist before publishing a versioned release.
