# Local Demonstration Runbook

This runbook prepares a repeatable local showcase using synthetic records only.

## Safety and scope

- Use a disposable local SQLite database.
- Do not point the demo seeder at a customer, production or shared database.
- The sample devices and SBOM are synthetic. They do not represent real products or real vulnerability intelligence.
- Keep the API bound to localhost. Do not expose the shared API key or operator console to the internet.
- The prototype does not scan networks, validate device identity or certify CRA compliance.

## 1. Prepare the environment

Create and activate a virtual environment, then install development dependencies as described in the README.

Set a one-off local API key:

**PowerShell**
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

## 2. Seed synthetic records

```bash
python -m app.seed
```

The seeder creates three example devices and imports the sample CycloneDX document for `CAM-002`. Re-running it against the same database does not reset existing data; use a fresh disposable database for a clean demonstration.

## 3. Start the application

```bash
uvicorn app.main:app --reload
```

Open:
- Operator console: `http://127.0.0.1:8000/`
- API documentation: `http://127.0.0.1:8000/docs`

Enter the same local API key into the console. It remains in page memory only.

## 4. Suggested walkthrough

1. **Overview:** show device count, open findings, high/critical findings and audit status.
2. **Inventory:** select `CAM-002` and explain its declared posture evidence and high-risk configuration.
3. **SBOM:** import `samples/sensor_sbom.json` for a device and explain that demo advisories are synthetic.
4. **Triage:** record a justified decision and show the corresponding audit event.
5. **Report:** download a JSON report and explain its evidence boundaries.
6. **Audit:** verify the hash chain and explain that this is tamper evidence, not immutable storage.

## 5. Clean up

Stop the server. Delete only the disposable local `devicetrust.db` file if you want to reset the demo. Do not delete a database whose contents matter.

## Evidence to capture

Capture genuine screenshots from the running application at desktop and mobile widths. Use synthetic data only. Avoid screenshots that expose API keys, environment variables, local usernames, file paths or private data. Record the exact commit SHA used for the capture.
