# Contributing

Thanks for taking an interest in DeviceTrust. The project is an evidence-oriented IoT product-security prototype; contributions should preserve its conservative evidence model and clearly documented limitations.

## Before opening a change

1. Read the [README](README.md), [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [prototype limitations](docs/prototype-limitations.md) and relevant domain documentation.
2. Open an issue first for substantial product, schema or architecture changes.
3. Create a focused branch from the current development base. Do not commit directly to `main`.
4. Keep pull requests small enough to review and explain.

## Engineering expectations

- Use Python 3.12 and follow the existing Ruff configuration.
- Validate untrusted input at the API boundary; use bounded fields and strict schemas.
- Preserve provenance, source timestamps and explicit unknown states.
- Never infer compliance from missing data.
- Do not auto-associate devices based only on MAC, IP, hostname, OUI or banners.
- Do not let clients self-assert evidence verification.
- Keep raw evidence and audit payloads free of secrets.
- Avoid network calls in tests; mock external services.
- Add tests for success, invalid input, authorization boundaries and failure paths.
- Update English documentation and the roadmap when behavior or limitations change.
- Do not add dependencies or infrastructure without a clear product need.

## Local checks

```bash
pip install -r requirements-dev.txt
pre-commit validate-config
pre-commit install-hooks
ruff check .
bandit -q -r app
pip-audit -r requirements.txt
pip-audit -r requirements-dev.txt
node --check web/app.js
pytest -q
```

## Pull request checklist

- [ ] Scope and user value are explained.
- [ ] Tests cover new behavior and relevant negative cases.
- [ ] Security and privacy implications are described.
- [ ] Documentation and prototype limitations are updated.
- [ ] No credentials, local databases, personal data or generated artifacts are included.
- [ ] CI checks pass.
- [ ] Claims in the PR are supported by code or test evidence.

## Responsible disclosure

Do not report vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md).
