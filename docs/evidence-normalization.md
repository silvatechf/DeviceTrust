# Evidence Normalization and Reviewed Association

**Status:** Design proposal
**Scope:** Milestone 2 foundation; no runtime behavior changes in this document.

## 1. Goals

- Preserve every submitted observation and its provenance.
- Provide a deterministic canonical vocabulary for attributes.
- Make source conflicts visible instead of silently overwriting values.
- Separate asset identification, device association and verification.
- Require an explicit operator decision before observations are attached to a different device.
- Keep posture assessment unchanged until normalized evidence rules have independent tests and an explicit policy.

## 2. Non-goals

- Automatic device identity resolution or automatic merging.
- Active network scanning, packet capture or hardware agents.
- Treating confidence labels as probabilities.
- Treating a SHA-256 digest as proof of origin or authenticity.
- Fetching or dereferencing evidence references.
- Inferring that an asset is secure because no observation or finding exists.

## 3. Canonical attribute vocabulary

Canonical names use lowercase dotted namespaces. Adapters map source-specific field names into this vocabulary; the original source attribute remains available for traceability.

| Canonical attribute | Meaning | Example value | Notes |
|---|---|---|---|
| `identity.manufacturer` | Claimed manufacturer | `Acme` | Claim, not attestation |
| `identity.model` | Claimed model | `GW-100` | May be ambiguous |
| `identity.serial_number` | Manufacturer serial | `SN123` | Sensitive operational identifier |
| `network.mac_address` | Observed MAC address | `02:00:00:00:00:01` | Spoofable; not identity proof |
| `network.ip_address` | Observed IP address | `192.0.2.10` | Time-bound and reusable |
| `network.hostname` | Observed hostname | `sensor-01` | Mutable and non-unique |
| `network.interface` | Interface identifier/type | `wlan0` | Source-specific detail may be retained |
| `firmware.version` | Claimed firmware version | `1.2.3` | Preserve exact vendor string |
| `firmware.build` | Firmware build identifier | `build-42` | Not necessarily comparable |
| `lifecycle.support_until` | Claimed support end date | `2030-12-31` | Date semantics must be explicit |
| `security.secure_boot` | Secure-boot state | `enabled` | Evidence must state how observed |
| `security.firmware_signed` | Firmware-signature state | `true` | Signature presence is not validation |
| `management.protocol` | Management protocol | `https` | Does not imply exposure |
| `management.internet_exposed` | Internet exposure claim | `false` | Scope and observation window matter |
| `sbom.component.purl` | Package URL | `pkg:pypi/example@1.0` | Normalize and validate before correlation |

Unknown attributes remain ingestible as unclassified observations; they must not be silently mapped to a semantically similar canonical attribute.

## 4. Normalized observation contract

A normalized view should be derived from, not replace, the immutable-in-practice raw observation record. The initial adapter contract should contain:

- `observation_id`: stable source record identifier.
- `source_type`: existing source allowlist.
- `source_attribute`: exact submitted attribute.
- `canonical_attribute`: nullable until mapped.
- `raw_value`: original bounded value, subject to existing access controls.
- `normalized_value`: nullable typed representation.
- `observed_at`: source observation time in UTC.
- `recorded_at`: server receipt time in UTC.
- `confidence`: descriptive source-quality label only.
- `verification_status`: server-controlled state.
- `evidence_reference` and `evidence_hash`: provenance pointers, not authenticity guarantees.
- `normalizer_name` and `normalizer_version`: reproducibility metadata.

Do not introduce this as a second writable source of truth until the adapter behavior and storage lifecycle are tested. A deterministic, pure normalization function is the preferred first implementation.

## 5. Value normalization rules

- Normalize only attributes with an explicit adapter rule.
- Preserve the raw value and original attribute exactly as submitted.
- Normalize case only where the attribute semantics are case-insensitive.
- Normalize MAC addresses to lowercase colon-separated form; retain the raw input.
- Parse IP addresses with a standard library parser and store canonical textual form.
- Normalize timestamps to UTC; reject naive timestamps.
- Treat firmware versions as opaque strings initially. Do not assume semantic-version compatibility unless the vendor/ecosystem is known.
- Parse booleans only from an explicit allowlist of representations; reject ambiguous strings.
- Validate Package URLs with the existing SBOM normalization boundary rather than creating a weaker second parser.
- Reject invalid known-attribute values from the normalized view while retaining the raw observation and recording a normalization error.
- Never transform an unknown attribute into a known attribute through fuzzy matching.

## 6. Conflict handling and temporal semantics

Different observations for the same canonical attribute are not duplicates merely because their values differ.

- Retain all observations with their source, timestamps and confidence.
- Group candidate values by canonical attribute and overlapping validity/observation windows.
- Present conflicts explicitly; do not select a winner using confidence alone.
- Prefer the most recent observation only when the attribute has time-varying semantics and the source timestamp is trustworthy enough for that use.
- IP address, hostname, MAC observation and exposure are time-bound facts, not permanent device properties.
- A newer observation does not erase an older record.
- Record operator resolution as a separate audited decision referencing the observations considered and the rationale.
- If temporal ordering is uncertain, show the values as unresolved rather than inventing a current value.

## 7. Identification and association policy

Evidence about an asset is not proof of its identity.

**Weak identifiers** (never sufficient for automatic association):
- MAC/OUI
- IP address
- hostname
- DNS/mDNS/SSDP name
- network banner or service fingerprint
- manufacturer/model inferred from a vendor prefix

**Potentially stronger identifiers** still require source and context review:
- manufacturer serial number
- hardware-backed device identity or certificate subject
- authenticated vendor inventory identifier
- operator-confirmed asset tag tied to physical inventory

A future reviewed-association action should:
1. Require an authenticated operator.
2. Accept one or more unassigned observation IDs and a target device ID.
3. Show the source, timestamps, raw/canonical values and conflicts before confirmation.
4. Require a justification with bounded length.
5. Record an audit event containing the observation IDs, target, actor and rationale; avoid copying sensitive raw values into the audit payload.
6. Preserve the original observation and its source metadata.
7. Reject unknown IDs, already-associated observations and invalid targets with deterministic errors.
8. Never silently move observations between devices. Corrections should be explicit, audited actions.

The current shared API key identifies only a broad operator boundary, not an individual. Until individual identities and authorization scopes exist, the association workflow must remain a local prototype capability and must not be represented as attributable human approval.

## 8. Verification states

Keep these concepts separate:

- **Unverified:** ingested but not independently checked.
- **Corroborated:** supported by independent evidence sources under an explicit rule.
- **Operator-reviewed:** an operator reviewed and accepted the association/interpretation; this is not cryptographic attestation.
- **Verified:** reserved for a documented verification method that actually validates the claim (for example, cryptographic validation of a device identity or firmware signature).

Do not let a client set these states. Do not label a claim verified merely because multiple weak sources repeat it; sources may share the same upstream data.

## 9. Security and privacy requirements

- Bound request size, record count, string lengths and pagination.
- Do not fetch user-supplied evidence references (SSRF boundary).
- Do not place raw observation values, serial numbers, IP addresses or credentials in audit payloads by default.
- Apply authentication and authorization to every read and write endpoint.
- Keep source timestamps separate from server receipt timestamps.
- Avoid logging secrets or full raw evidence.
- Treat imported router exports, SBOMs and firmware metadata as untrusted input.
- Preserve explicit unknown and conflict states in reports.
- Add retention and deletion policy before production use; current audit and evidence retention is not a complete privacy lifecycle.

## 10. Implementation sequence and acceptance criteria

### Step A — Pure normalization module
- Add a canonical attribute registry and source adapters in a dedicated module.
- Add unit tests for valid, invalid, unknown and ambiguous values.
- Ensure normalization is deterministic and preserves raw inputs.
- No database schema change and no posture integration.

### Step B — Read-only normalized projection
- Expose normalized values through a bounded read path without modifying stored observations.
- Include normalizer version and normalization errors.
- Test pagination, authorization, unknown attributes and conflicting values.

### Step C — Reviewed association
- Add an explicit association endpoint only after identity policy and actor limitations are resolved.
- Require justification and audit event.
- Test replay, duplicate association, invalid target, unauthorized access and audit failure behavior.

### Step D — Posture integration
- Define per-control evidence acceptance rules, freshness windows and minimum corroboration.
- Keep unknown when evidence is absent, stale, conflicting or insufficient.
- Add adversarial tests before enabling any evidence-driven posture calculation.

## 11. Current implementation boundary

The current API stores unverified observations, optionally linked to an existing device, and lists them with bounded offset pagination. A side-effect-free normalizer now provides a versioned read-only projection for selected identity, network, firmware and security attributes through `GET /evidence/normalized`. It preserves raw values, leaves unknown attributes unclassified and reports invalid known values without coercion. It does not resolve identity, associate unassigned observations, resolve source conflicts or feed observations into posture. The normalizer is an initial prototype, not a complete source-adapter framework.
