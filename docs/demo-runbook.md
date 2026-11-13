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

It then imports `samples/cold_chain_gateway_sbom.json` for `EDGE-GW-003` through the legacy device-scoped SBOM endpoint.

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

## 4. Demonstrate persistent product-release SBOM inventory

The product-scoped API is separate from the legacy device-scoped SBOM workflow. It stores accepted import metadata and component occurrences against a declared product release. It does not infer that a product release belongs to a device.

The following commands use cURL. In Windows PowerShell, use `curl.exe` rather than the `curl` alias. Run each cURL command as a single line. Keep the API key local and do not paste it into shared logs or screenshots.

Set the key in the shell used for the commands:

**Windows PowerShell**
```powershell
$env:API_KEY = $env:DEVICETRUST_API_KEY
```

**macOS / Linux**
```bash
export API_KEY="$DEVICETRUST_API_KEY"
```

Create a declared product identity:

```bash
curl -sS -X POST http://127.0.0.1:8000/products -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d '{"manufacturer":"Synthetic Cold Chain Systems","product_name":"Edge Gateway","external_reference":"DEMO-GW"}'
```

Copy the returned `id` and use it as `PRODUCT_ID` below. Create a product release:

```bash
curl -sS -X POST "http://127.0.0.1:8000/products/PRODUCT_ID/releases" -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d '{"version":"3.1.0","hardware_revision":"A","release_reference":"DEMO-3.1.0"}'
```

Copy the returned `id` as `RELEASE_ID`. Import the sample SBOM using the exact file bytes:

The authenticated CLI can perform this import without placing the API key in command-line arguments. Configure `DEVICETRUST_API_URL` and `DEVICETRUST_API_KEY` as described in section 8, then run:

```bash
python -m app.cli import --release-id RELEASE_ID --file samples/cold_chain_gateway_sbom.json --source-reference local-demo-cli
```

The CLI marks this source as `pipeline`. It does not create the product or release; those records must already exist. The API remains responsible for CycloneDX validation, persistence and digest-based duplicate handling. Use either the CLI command above or the cURL example below for a single initial import; do not run both unless you intentionally want to demonstrate an idempotent repeat.


```bash
curl -sS -X POST "http://127.0.0.1:8000/product-releases/RELEASE_ID/sbom?source_type=manual&source_reference=local-demo" -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" --data-binary "@samples/cold_chain_gateway_sbom.json"
```

The response includes the import ID, SHA-256 digest, parser/spec version, component count and a `created` flag. An identical import for the same release and format is idempotent: the existing import is returned with `created: false`. The route responds with HTTP 201 in either case. The raw SBOM document is not retained; the accepted parsed component snapshot and digest are persisted.

Copy the returned import `id` as `IMPORT_ID`. Inspect accepted imports and their component occurrences:

```bash
curl -sS "http://127.0.0.1:8000/product-releases/RELEASE_ID/sbom" -H "X-API-Key: $API_KEY"
curl -sS "http://127.0.0.1:8000/sbom/imports/IMPORT_ID/components" -H "X-API-Key: $API_KEY"
```

### Compare two accepted imports for the same product release

The comparison endpoint is read-only. To make the change visible, create a second synthetic SBOM with a changed version and one added component. This is demonstration data only.

Import a second document into the same `RELEASE_ID`:

```bash
curl -sS -X POST "http://127.0.0.1:8000/product-releases/RELEASE_ID/sbom?source_type=manual&source_reference=local-demo-comparison" -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"requests","version":"2.32.0","purl":"pkg:pypi/requests@2.32.0"},{"type":"library","name":"demo-added-lib","version":"1.0.0","purl":"pkg:generic/demo-added-lib@1.0.0"}]}'
```

List the imports again and copy the IDs for the original and follow-up imports. Keep the same release ID; the endpoint rejects imports from another release.

```bash
curl -sS "http://127.0.0.1:8000/product-releases/RELEASE_ID/sbom" -H "X-API-Key: $API_KEY"
```

Compare the original import to the follow-up import:

```bash
curl -sS "http://127.0.0.1:8000/product-releases/RELEASE_ID/sbom/diff?from_import_id=BASELINE_IMPORT_ID&to_import_id=FOLLOWUP_IMPORT_ID" -H "X-API-Key: $API_KEY"
```

Inspect the summary and component groups: the changed `requests` version should be reported as changed, and `demo-added-lib` as added. The result can also include removed, unchanged, ambiguous and unidentified components depending on the source SBOMs. Matching uses PURL identity with only the version segment excluded; qualifiers and subpath remain significant. This is a bounded structural comparison, not proof of artifact/supplier equivalence or a vulnerability re-assessment.

The comparison GET does not create audit events or mutate either import. Do not infer that a missing or unidentified component is safe.

For a component with findings, use its returned component `id`:

```bash
curl -sS "http://127.0.0.1:8000/sbom/components/COMPONENT_ID/findings" -H "X-API-Key: $API_KEY"
```

These endpoints expose the persisted product/release/import/component provenance. Findings are synthetic demo intelligence and must not be treated as a complete vulnerability assessment. The product-scoped workflow is API-only; the local console walkthrough below uses the legacy device-scoped demonstration.

## 5. Suggested console walkthrough

1. **Overview:** show the three registered assets, synthetic findings and audit-chain status.
2. **Inventory — refrigeration controller:** select `COLD-CTRL-001`; explain that missing firmware-integrity evidence remains unverified.
3. **Inventory — temperature sensor:** select `TEMP-SENSOR-002`; explain why unknown identity and security attributes are not treated as compliant.
4. **Inventory — edge gateway:** select `EDGE-GW-003`; compare its declared profile with the other assets and inspect its generated vulnerability findings.
5. **SBOM import:** explain that the seeder imported a synthetic CycloneDX document for `EDGE-GW-003`. The current console displays resulting vulnerability findings, not a persistent component inventory or full SBOM viewer.
6. **Triage:** record a reasoned demonstration decision. Do not interpret it as a real maintenance recommendation.
7. **Report:** download the JSON report for `EDGE-GW-003`.
8. **Audit:** verify the hash chain and explain that this is tamper evidence, not immutable storage.

## 6. Clean up

Stop the server. Delete only the disposable local `devicetrust.db` file if you want to reset the demo. Do not delete a database whose contents matter.

## 7. Evidence to capture

Capture genuine screenshots from the running application at desktop and mobile widths. Use synthetic data only. Avoid screenshots that expose API keys, environment variables, local usernames, file paths or private data. Record the exact commit SHA used for the capture.



### Reassess a stored product SBOM import

After the local database has been migrated with `alembic upgrade head`, request a new assessment for the accepted import:

```bash
curl -sS -X POST "http://127.0.0.1:8000/sbom/imports/IMPORT_ID/assessments" -H "X-API-Key: $API_KEY" -H "Idempotency-Key: demo-assessment-001"
```

The request returns an assessment ID, component/finding counts, timestamps, source fingerprint, aggregate coverage status and provider-specific enrichment metadata under `enrichment_metadata.osv` and `enrichment_metadata.intelligence`. Repeating the same request with the same key and source configuration returns the existing assessment. Use a new key to deliberately append another assessment run.

List the assessment history:

```bash
curl -sS "http://127.0.0.1:8000/sbom/imports/IMPORT_ID/assessments" -H "X-API-Key: $API_KEY"
```

Inspect findings from one specific assessment:

```bash
curl -sS "http://127.0.0.1:8000/sbom/imports/IMPORT_ID/assessments/ASSESSMENT_ID/findings" -H "X-API-Key: $API_KEY"
```

Assessment findings are separate from the original import-time findings and their human triage fields. A new assessment does not inherit or overwrite prior triage decisions. An OSV status of `disabled` means OSV enrichment was not run; it does not mean that the import has no vulnerabilities. `incomplete` means the available intelligence did not cover the entire requested assessment.

Versioned reassessment history and KEV/EPSS enrichment are integrated into `main` through PRs #45 and #55. OSV and external intelligence feeds remain best-effort sources and do not provide a globally consistent snapshot.


### Optional KEV and EPSS enrichment

After the database has been upgraded with `alembic upgrade head`, enable either provider independently for a local assessment.

**Windows PowerShell**
```powershell
$env:DEVICETRUST_KEV = "1"
$env:DEVICETRUST_EPSS = "1"
```

**macOS / Linux**
```bash
export DEVICETRUST_KEV=1
export DEVICETRUST_EPSS=1
```

Create a new assessment with a new idempotency key:

```bash
curl -sS -X POST "http://127.0.0.1:8000/sbom/imports/IMPORT_ID/assessments" -H "X-API-Key: $API_KEY" -H "Idempotency-Key: kev-epss-demo-001"
```

Inspect the findings for that assessment:

```bash
curl -sS "http://127.0.0.1:8000/sbom/imports/IMPORT_ID/assessments/ASSESSMENT_ID/findings" -H "X-API-Key: $API_KEY"
```

The response records per-finding KEV and EPSS states and provider provenance. KEV membership includes the CISA catalog version/release date and entry details. The assessment-level `status` aggregates OSV, KEV and EPSS coverage: any incomplete enabled provider makes the run incomplete; at least one complete provider with no incomplete provider makes it complete; all disabled/not-applicable providers produce disabled. EPSS includes score, percentile and score date. Both are CVE-level signals: they do not prove that a specific product component is affected.

Provider states such as `disabled`, `not_checked`, `not_applicable`, `not_found`, `unavailable` and `incomplete` are intentionally distinct. A missing EPSS record or absent KEV membership is not proof that a vulnerability is harmless. Enrichment is bounded to 100 unique CVEs per assessment; provider failures do not erase the local or OSV findings.

Do not interpret KEV membership or EPSS scores as an automatic affected/not-affected decision, CRA reporting trigger or VEX statement. Those decisions require product-version applicability analysis and attributable human review. See [DEC-009](decisions/DEC-009-kev-epss-enrichment.md).


## 8. Use the assessment CLI

The CLI is an authenticated HTTP client. It uses the same API routes, authentication mode and authorization policies as other clients; it does not connect directly to the database.

Configure the API endpoint and credential in the shell. Keep the token out of command-line arguments and logs.

**Windows PowerShell**
```powershell
$env:DEVICETRUST_API_URL = "http://127.0.0.1:8000"
$env:DEVICETRUST_API_KEY = "your-local-api-key"
```

**macOS / Linux**
```bash
export DEVICETRUST_API_URL="http://127.0.0.1:8000"
export DEVICETRUST_API_KEY="your-local-api-key"
```

If you have not imported the SBOM in section 4, first create the product and release there, then use the CLI import command shown in that section. Copy the import `id` from its JSON response.

Run an assessment. The idempotency key is required; reusing it with unchanged source configuration returns the existing run, while a new key requests a new historical run.

```bash
python -m app.cli assess --import-id IMPORT_ID --idempotency-key demo-assessment-001
```

List the assessment history:

```bash
python -m app.cli history --import-id IMPORT_ID
```

Inspect findings from a specific run:

```bash
python -m app.cli findings --import-id IMPORT_ID --assessment-id ASSESSMENT_ID
```

All successful responses are JSON on stdout. Errors are JSON on stderr. Exit codes: `0` success, `2` local configuration/usage, `3` network/timeout, `4` authentication/authorization, `5` API request rejection, and `6` API server/unexpected response. Non-loopback endpoints must use HTTPS. Use `python -m app.cli --help` for command options.


## 9. Verified local product SBOM walkthrough (2026-11-13)

A manual run against `main` commit `d8587e0` completed using the API and CLI with a disposable SQLite database under the operating-system temporary directory and a localhost-only API process on port 8766.

Observed results:

- Product, product release, CycloneDX SBOM import and assessment were created successfully in the disposable database.
- The official `GET /audit/verify` endpoint returned `valid: true` with four verified entries.
- `GET /audit` returned four audit events.
- The API process was stopped after the run. The temporary API key was removed from the PowerShell process environment.
- The temporary SQLite database and API stdout/stderr logs were preserved outside the repository.

The record IDs (`1` for product, release, import and assessment) are local to that disposable database and must not be treated as shared or production identifiers.

This manual run did not test the browser console, external vulnerability-intelligence providers, human decision/signature/approval, VEX export, production deployment or recovery procedures. It does not establish production readiness. The integrated automated API/CLI review-to-VEX test remains the evidence for the decision, evidence-manifest, signature, independent-approval and VEX path.
