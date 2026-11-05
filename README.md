# DeviceTrust

**An evidence-oriented IoT/OT security assessment and vulnerability-triage prototype, initially focused on food production, processing and cold-chain environments.**

[![CI](https://github.com/silvatechf/DeviceTrust/actions/workflows/ci.yml/badge.svg)](https://github.com/silvatechf/DeviceTrust/actions/workflows/ci.yml)
[![CodeQL](https://github.com/silvatechf/DeviceTrust/actions/workflows/codeql.yml/badge.svg)](https://github.com/silvatechf/DeviceTrust/actions/workflows/codeql.yml)

DeviceTrust explores how teams can organise connected-asset information, assess declared security posture, analyse supported software-component inventories, document vulnerability-triage decisions and retain traceable evidence.

The initial application context is **food production, processing, storage and cold-chain operations**. Agriculture and precision-farming environments are adjacent expansion areas, subject to market validation. The initial target users are expected to include OT/automation integrators, specialist security consultancies and food-sector infrastructure teams.

> **Current status:** early-stage Python/FastAPI prototype for local technical evaluation, not a production security platform. DeviceTrust does not actively discover devices, independently verify device claims, detect intrusions, prevent attacks or certify regulatory compliance.

## Product positioning and market scope

See [Market Positioning](docs/market-positioning.md) for the target users, initial use case, competitive boundaries, market-validation plan and claims policy.

The product direction is deliberately evidence-oriented: connect asset records, declared posture, supported SBOM analysis, vulnerability triage and audit context without treating missing or unverified information as proof of safety.

## The current prototype

The application is built with Python, FastAPI, Pydantic and SQLAlchemy. It is a modular monolith intended for local evaluation and technical learning.

Implemented prototype workflows:

1. Store device inventory and declared security attributes.
2. Assess declared profiles and keep missing information as `unverified`.
3. Accept bounded evidence observations while preserving source and timestamps.
4. Parse a supported subset of CycloneDX JSON and match components against synthetic demo advisories; optionally query OSV.
5. Record vulnerability-triage decisions with a mandatory justification.
6. Generate JSON/Markdown reports and verify a SHA-256-linked audit history.
7. Use a same-origin local operator console.

Evidence observations are currently stored separately from posture inputs. Ingestion does not prove a claim, identify a device or change its posture result.

## What is not implemented

- Active LAN discovery, packet capture or device agents.
- Independent device identity, firmware-signature or hardware attestation.
- Automatic association of unassigned observations with devices.
- Evidence-driven posture calculations or source-conflict resolution.
- Full CycloneDX schema/dependency-graph validation or complete CVE coverage.
- Individual operator accounts, RBAC, tenant isolation or production browser sessions.
- Immutable/WORM audit storage, external audit checkpoints or multi-writer serialization.
- Production operations, real-time intrusion detection, incident-response automation or CRA conformity assessment.

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

### 2. Start the API

```bash
uvicorn app.main:app --reload
```

- Operator console: http://127.0.0.1:8000/
- Interactive API documentation: http://127.0.0.1:8000/docs

The console receives the shared API key in browser memory. Use it only with a trusted local instance. Do not expose the service or key to the public internet.

### 3. Load synthetic demo data (optional)

Use a dedicated disposable SQLite file for the demonstration. Do not point the seeder at a database containing data you need to preserve.

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

The seeder creates three synthetic devices and imports the sample CycloneDX document for `EDGE-GW-003`. It does not reset an existing database; the dedicated filename keeps this walkthrough separate from the default `devicetrust.db`. See the [Demo runbook](docs/demo-runbook.md).

## Optional PostgreSQL setup

Copy `.env.example` to `.env`, replace both placeholders with independent random secrets, then run:

```bash
docker compose up --build
```

The API port is bound to localhost. Keep `.env` private and never commit it. PostgreSQL support is configurable, but integration, restart and backup/restore behavior still require manual verification.

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
- Submitted device and evidence claims are not independent attestation.
- Weak identifiers such as MAC, IP and hostname are not identity proof.
- Vulnerability triage requires a written justification.
- Audit hash chaining provides tamper evidence, not immutable storage.
- External intelligence failures or missing results do not mean that a component is vulnerability-free.
- DeviceTrust is an assessment and evidence-management prototype, not an inline IDS/IPS or OT safety controller.

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Contributions should follow [CONTRIBUTING.md](CONTRIBUTING.md).

## Technical documentation

| Document | What it helps explain |
|---|---|
| [Market positioning](docs/market-positioning.md) | Target market, buyer hypotheses, initial use case and claims policy |
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

- NISTIR 8259 — Foundational Cybersecurity Activities for IoT Device Manufacturers.
- CycloneDX — Software Bill of Materials (SBOM) standard.
- OSV — Open Source Vulnerabilities database and API.
- CISA Known Exploited Vulnerabilities (KEV) Catalog.
- Regulation (EU) 2024/2847 — Cyber Resilience Act.

## License

No license has been selected. Until one is added, all rights are reserved. See the release-readiness checklist before publishing a versioned release.
