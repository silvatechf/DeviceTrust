# Prototype Limitations

The code is an early development prototype, not a production security product.

- The API uses a shared API key; it is not tenant-aware and has no RBAC.
- The audit chain is tamper-evident only; it is not immutable.
- `support_until` is the only lifecycle signal currently stored.
- Internet exposure is declared metadata, not independently discovered reachability.
- The local advisory JSON is demonstration data, not a maintained vulnerability feed.
- Optional OSV lookup needs version-range and ecosystem-aware matching before findings are considered reliable.
- The SBOM parser is a limited CycloneDX reader, not a complete schema validator.
- Security profile fields are declarations and are not independently verified device measurements.
- Evidence observations preserve source type, source time, recording time, confidence and optional artifact digest. They default to unverified and do not yet drive posture calculations or automatic device association.
- Evidence references are opaque strings; artifacts are not retained or fetched by the application. A supplied digest does not authenticate the source.
- DeviceTrust does not prevent attacks or function as an inline IDS/IPS or safety controller.
