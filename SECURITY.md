# Security Policy

## Supported versions

DeviceTrust is an early-stage prototype. Security fixes are applied to the active development branch; no stable release or supported-version policy has been established.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in a public issue, pull request, discussion, screenshot or social post.

Use GitHub's private vulnerability reporting / Security Advisories feature for this repository if it is enabled. If private reporting is unavailable, contact the repository maintainer through the contact route on the GitHub profile and request a private channel before sharing technical details.

Include, where safe:
- affected commit or branch;
- component and endpoint;
- impact and realistic attack prerequisites;
- minimal reproduction steps or a proof of concept;
- suggested mitigation, if known.

Do not include real credentials, customer data, personal data or data belonging to systems you do not own or have explicit permission to test. Do not perform destructive testing, denial of service, social engineering or testing against third-party devices.

The maintainer will acknowledge reports when reasonably possible and may request clarification. This project has no formal bug-bounty programme or guaranteed response SLA.

## Security boundaries

The current prototype uses a shared API key and a local operator console that receives that key in browser memory. It is not designed for public internet exposure, multi-tenant use or production security operations. See [the threat model](docs/threat-model.md), [operator console boundary](docs/operator-console.md) and [prototype limitations](docs/prototype-limitations.md).
