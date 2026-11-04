# DeviceTrust

**Evidence-oriented IoT Product Security & Lifecycle Management prototype**

[![CI](https://github.com/silvatechf/DeviceTrust/actions/workflows/ci.yml/badge.svg)](https://github.com/silvatechf/DeviceTrust/actions/workflows/ci.yml)
[![CodeQL](https://github.com/silvatechf/DeviceTrust/actions/workflows/codeql.yml/badge.svg)](https://github.com/silvatechf/DeviceTrust/actions/workflows/codeql.yml)

DeviceTrust explores how IoT product-security teams can organize device inventory, security posture evidence, SBOM component findings and auditable triage decisions in one lightweight workflow.

> **Project status:** early-stage prototype for local technical evaluation. It is not a production security platform, active network scanner, device-protection system or Cyber Resilience Act (CRA) conformity assessment.

## What works in this prototype

- FastAPI API with shared API-key authentication.
- Device inventory and declared security-profile assessment.
- Explicit `unverified` posture when evidence is missing or insufficient.
- Bounded evidence observation ingestion, including unassigned observations.
- Read-only normalization projection for selected identity, network, firmware and security attributes.
- Bounded CycloneDX JSON ingestion and PURL-based component matching.
- Synthetic local demonstration advisories and optional best-effort OSV lookup.
- Vulnerability triage with mandatory justification.
- JSON and Markdown device reports.
- SHA-256 hash-chained audit events and integrity verification.
- Same-origin local operator console for inventory, posture, SBOM, triage, reports and audit review.

## What it does not do

- Discover devices through active LAN scanning or packet capture.
- Independently attest device identity, firmware integrity or security declarations.
- Automatically associate unassigned evidence with devices.
- Feed normalized observations into posture calculations.
- Provide complete CVE coverage or complete CycloneDX schema validation.
- Provide individual user identities, RBAC, tenant isolation or production browser sessions.
- Prevent attacks, control physical equipment or certify CRA compliance.

See [Prototype Limitations](docs/prototype-limitations.md) and the [Threat Model](docs/threat-model.md) before evaluating the project.

## Architecture

DeviceTrust is a modular monolith built with Python 3.12, FastAPI, Pydantic and SQLAlchemy. SQLite is the default local database; PostgreSQL can be configured with `DATABASE_URL`.

The [architecture reference](docs/architecture.md) includes editable Mermaid diagrams, trust boundaries and a clear distinction between implemented and planned capabilities.

## Quick start — local SQLite

### 1. Create an environment

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

Keep the API key local. Do not commit it or reuse a production credential.

### 2. Start the API

```bash
uvicorn app.main:app --reload
```

- Operator console: http://127.0.0.1:8000/
- Interactive API documentation: http://127.0.0.1:8000/docs

The operator console receives the shared API key in browser memory. Use it only with a trusted local instance; do not expose it to the public internet.

### 3. Optional synthetic demo data

Stop any running instance first if you want a clean disposable database. Then:

```bash
python -m app.seed
```

The seeder creates three synthetic devices and imports the sample CycloneDX document for `CAM-002`. It does not reset an existing database. Use a fresh disposable database for a clean walkthrough. See the [Demo Runbook](docs/demo-runbook.md).

## Optional Docker Compose — PostgreSQL

Copy `.env.example` to `.env`, replace both placeholders with independent random hexadecimal secrets, and then run:

```bash
docker compose up --build
```

The API port is bound to `127.0.0.1`. Keep the environment file private and never commit `.env`. The Compose configuration requires explicit secrets and does not fall back to a known default database password.

## Quality checks

```bash
ruff check .
bandit -q -r app
pip-audit -r requirements.txt
node --check web/app.js
pytest -q
```

GitHub Actions runs these checks on pushes and pull requests. CodeQL analysis is configured separately. A green CI run is useful evidence, not proof that the application is secure or production-ready.

## Security model

1. Missing data is not evidence of compliance.
2. Evidence observations preserve source and time context and remain unverified by default.
3. Weak identifiers such as MAC, IP, hostname, OUI and banners are not proof of device identity.
4. Risk acceptance requires a recorded justification.
5. Audit hash chains provide tamper evidence, not immutable storage.
6. DeviceTrust is an assessment and evidence-management prototype, not an inline IDS/IPS or OT safety controller.

Please read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Contributions should follow [CONTRIBUTING.md](CONTRIBUTING.md).

## Technical documentation

- [Engineering decisions](docs/engineering-decisions.md)
- [Test matrix and verification evidence](docs/test-matrix.md)
- [Architecture and data flows](docs/architecture.md)
- [Security controls and evidence model](docs/security-controls.md)
- [Threat model and residual risks](docs/threat-model.md)
- [Evidence ingestion API](docs/evidence-ingestion.md)
- [Evidence normalization and association design](docs/evidence-normalization.md)
- [Operator console and its security boundary](docs/operator-console.md)
- [Local demonstration runbook](docs/demo-runbook.md)
- [Prototype limitations](docs/prototype-limitations.md)
- [Release readiness checklist](docs/release-readiness.md)
- [Roadmap](docs/roadmap.md)
- [Changelog](CHANGELOG.md)

## References

- NISTIR 8259 — Foundational Cybersecurity Activities for IoT Device Manufacturers.
- CycloneDX — Software Bill of Materials standard.
- OSV — Open Source Vulnerabilities database and API.
- CISA Known Exploited Vulnerabilities (KEV) Catalog.
- Regulation (EU) 2024/2847 — Cyber Resilience Act.

## License

No license has been selected yet. Until the copyright holder chooses and adds a license, all rights are reserved and reuse, modification or redistribution are not granted. See the release-readiness checklist before publishing a versioned release.
