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
- DeviceTrust does not prevent attacks or function as an inline IDS/IPS or safety controller.
