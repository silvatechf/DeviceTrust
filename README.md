# DeviceTrust

**IoT Product Security & Lifecycle Management**

DeviceTrust is an evidence-oriented platform prototype for tracking IoT device inventory, assessing security posture, correlating software components with vulnerability intelligence, and maintaining auditable security decisions.

> **Status:** early prototype. DeviceTrust supports assessment and evidence management. It does not certify Cyber Resilience Act (CRA) compliance, replace manufacturer security processes, or protect/contain physical devices by itself.

## Current prototype

- FastAPI API with API-key authentication.
- Device registration and retrieval.
- Evidence-oriented security posture; missing evidence remains `unverified`.
- CycloneDX JSON component import.
- PURL-scoped local demonstration advisories and optional version-scoped OSV lookup (not a comprehensive vulnerability feed).
- Vulnerability triage with mandatory justification.
- JSON and Markdown device reports.
- SHA-256 hash-chained audit entries and integrity verification.
- Initial internet-exposure and management-interface findings.

## Planned capabilities

| Capability | Status |
|---|---|
| Device inventory | Prototype |
| Evidence-based posture | Prototype |
| CycloneDX SBOM ingestion | Prototype |
| Vulnerability intelligence | Prototype; matching limitations remain |
| Internet exposure and management-plane inventory | Initial implementation |
| Product and firmware EOL lifecycle | Planned |
| CISA KEV enrichment | Planned |
| Security event monitoring | Planned |
| Refrigeration tampering simulation | Planned vertical demo |
| Multi-tenant identity and RBAC | Planned |

## Architecture

The project starts as a **modular monolith**: FastAPI API layer, Pydantic validation, SQLAlchemy persistence, domain services and an evidence-oriented audit trail. SQLite is used by default; configuration is PostgreSQL-ready.

## Quick start

```bash
python -m venv .venv
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
```

Set a local development API key before running:

```powershell
$env:DEVICETRUST_API_KEY = "replace-with-a-local-development-secret"
uvicorn app.main:app --reload
```

On macOS/Linux:

```bash
export DEVICETRUST_API_KEY="replace-with-a-local-development-secret"
uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`; interactive documentation is at `/docs`. Do not expose this development configuration to a network.

## Tests

```bash
ruff check .
bandit -q -r app
pip-audit -r requirements.txt
pytest -q
```

## Security principles

1. Missing data is not evidence of compliance.
2. Findings require provenance and version-aware correlation.
3. Risk acceptance requires a recorded justification.
4. Hash chains provide tamper evidence, not immutable storage against a privileged database attacker.
5. Internet exposure and management access are separate from device-reported posture.
6. DeviceTrust is an assessment and evidence platform, not an inline IDS/IPS or OT safety controller.

## References

- NISTIR 8259 — Foundational Cybersecurity Activities for IoT Device Manufacturers.
- CycloneDX — Software Bill of Materials standard.
- OSV — Open Source Vulnerabilities database and API.
- CISA Known Exploited Vulnerabilities (KEV) Catalog.
- Regulation (EU) 2024/2847 — Cyber Resilience Act.

## License

No license has been selected yet. Until a license is added, all rights are reserved by the copyright holder.
