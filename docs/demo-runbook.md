# Local Demonstration Runbook

This runbook prepares a repeatable, synthetic food-processing and cold-chain showcase.

## Safety and scope

- Use a disposable local SQLite database.
- Do not point the demo seeder at a customer, production or shared database.
- All three devices, the vendor name, SBOM and local advisories are synthetic.
- The SBOM components are generic demonstration package identifiers, not a verified bill of materials from a real refrigeration controller.
- Keep the API bound to localhost. Do not expose the shared API key or operator console to the internet.
- The prototype does not scan networks, validate device identity, monitor temperatures, control refrigeration equipment or certify CRA compliance.
- Do not use the demonstration findings as operational vulnerability intelligence or maintenance instructions.

## 1. Prepare the environment

Create and activate a virtual environment, then install development dependencies as described in the README.

Set a one-off local API key:

**Windows PowerShell**
```powershell
$env:DEVICETRUST_API_KEY = "replace-with-a-random-local-secret"
Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
```

**macOS / Linux**
```bash
export DEVICETRUST_API_KEY="replace-with-a-random-local-secret"
unset DATABASE_URL
```

Leaving `DATABASE_URL` unset uses the default local `devicetrust.db`. Confirm that this file is disposable before running the seeder.

## 2. Apply migrations and seed synthetic records

For a clean walkthrough, use a fresh disposable database. The seeder applies pending Alembic migrations before writing, checks for conflicting device IDs and does not reset or overwrite existing records.

To apply migrations separately before starting the API:

```bash
alembic upgrade head
```

```bash
python -m app.seed
```

The seeder registers three synthetic assets:

| Device ID | Demonstration role | Data quality |
|---|---|---|
| `COLD-CTRL-001` | Refrigeration controller | Several declared controls; firmware-integrity fields remain unknown |
| `TEMP-SENSOR-002` | Cold-room temperature sensor | Identity and several security controls remain unverified |
| `EDGE-GW-003` | Industrial edge gateway | Stronger declared profile for comparison |

It then imports `samples/cold_chain_gateway_sbom.json` for `EDGE-GW-003`.

The sample SBOM uses generic PURLs and synthetic local advisories. Findings such as `DT-DEMO-0001` are deliberately fabricated to demonstrate the workflow. They are not real CVEs, vendor advisories or confirmed vulnerabilities.

If the database already contains one of the demo IDs, the seeder aborts before creating any records. Use a fresh disposable database rather than deleting a database whose contents matter.


### Existing SQLite database created before Alembic

The initial migration creates the current schema; it is not an automatic conversion migration for a database that already contains the legacy tables.

Before adopting an existing database:

1. Stop the application and make a verified backup of the SQLite file.
2. Confirm the existing tables and columns match `migrations/versions/0001_initial_schema.py`. Do not stamp an unknown or modified schema.
3. Point `DATABASE_URL` to that database and mark the baseline as applied without recreating tables:

```bash
alembic stamp 0001_initial
alembic current
```

4. Start the application and verify representative records and relationships.

If the schema differs, do not stamp it. Preserve the original file and prepare a reviewed data/schema migration first. Never run `alembic downgrade base` against a database containing data you need: the baseline downgrade drops all four application tables.

## 3. Start the application

```bash
uvicorn app.main:app --reload
```

Open:
- Operator console: `http://127.0.0.1:8000/`
- Interactive API documentation: `http://127.0.0.1:8000/docs`

Enter the same local API key into the console. It remains in page memory only.

## 4. Suggested walkthrough

1. **Overview:** show the three registered assets, synthetic findings and audit-chain status.
2. **Inventory — refrigeration controller:** select `COLD-CTRL-001`; explain that missing firmware-integrity evidence remains unverified.
3. **Inventory — temperature sensor:** select `TEMP-SENSOR-002`; explain why unknown identity and security attributes are not treated as compliant.
4. **Inventory — edge gateway:** select `EDGE-GW-003`; compare its declared profile with the other assets and inspect its generated vulnerability findings.
5. **SBOM import:** explain that the seeder imported a synthetic CycloneDX document for `EDGE-GW-003`. The current console displays resulting vulnerability findings, not a persistent component inventory or full SBOM viewer.
6. **Triage:** record a reasoned demonstration decision. Do not interpret it as a real maintenance recommendation.
7. **Report:** download the JSON report for `EDGE-GW-003`.
8. **Audit:** verify the hash chain and explain that this is tamper evidence, not immutable storage.

## 5. Clean up

Stop the server. Delete only the disposable local `devicetrust.db` file if you want to reset the demo. Do not delete a database whose contents matter.

## Evidence to capture

Capture genuine screenshots from the running application at desktop and mobile widths. Use synthetic data only. Avoid screenshots that expose API keys, environment variables, local usernames, file paths or private data. Record the exact commit SHA used for the capture.
