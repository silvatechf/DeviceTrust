# Evidence Normalization and Association

## Current implementation

A pure normalizer maps selected submitted attributes to canonical names and normalized values. The API exposes the result through `GET /evidence/normalized`.

The projection:
- preserves the original attribute and raw value;
- returns a canonical attribute and normalized value when a rule exists;
- reports invalid known values without silently coercing them;
- leaves unknown attributes unclassified;
- includes a normalizer version;
- does not change the stored observation, verification state or posture result.

This is an initial implementation for selected identity, network, firmware and security attributes. It is not a complete source-adapter framework.

## Why normalize?

Different sources may express the same attribute in different formats. A canonical vocabulary makes later comparison easier, but a bad mapping can create false certainty. DeviceTrust therefore normalizes only attributes with explicit rules and keeps the original input available for review.

## Example canonical attributes

| Canonical attribute | Example | Important limitation |
|---|---|---|
| `identity.manufacturer` | `Acme` | Claim, not attestation |
| `identity.model` | `GW-100` | May be ambiguous |
| `network.mac_address` | `02:00:00:00:00:01` | Spoofable; not identity proof |
| `network.ip_address` | `192.0.2.10` | Time-bound and reusable |
| `network.hostname` | `sensor-01` | Mutable and non-unique |
| `firmware.version` | `1.2.3` | Vendor formats may not be comparable |
| `security.secure_boot` | `enabled` | Must state how it was observed |
| `management.internet_exposed` | `false` | Scope and observation window matter |
| `sbom.component.purl` | `pkg:pypi/example@1.0` | Must be validated before correlation |

Unknown attributes remain unclassified; the normalizer does not guess a similar canonical name.

## Normalization rules

- Preserve the raw attribute and value.
- Normalize only when a specific rule exists.
- Parse IP addresses using standard library parsing.
- Normalize MAC addresses to a canonical representation.
- Parse boolean values only from an explicit set of accepted representations.
- Keep firmware versions as opaque strings unless their ecosystem defines comparison semantics.
- Reuse the SBOM PURL validation boundary rather than introducing a weaker parser.
- Keep invalid known values in the raw observation and report a normalization error.

## Identity and association are separate

An observation about an asset is not proof of which device produced it.

Weak identifiers such as MAC, IP, hostname, OUI and network banners must not be sufficient for automatic association. Stronger identifiers, including serial numbers or hardware-backed identity, still need source and context review.

**Automatic association, conflict resolution and operator-reviewed association are not implemented.** The current shared API key does not identify an individual operator, so it cannot support attributable human approval.

## Future association requirements

Before adding reviewed association, the project needs:
1. Individual operator identity and authorization.
2. A review screen showing source, timestamps, raw/canonical values and conflicts.
3. A required bounded justification.
4. An audit event referencing observations, target device, actor and rationale.
5. Tests for invalid IDs, duplicate/replayed actions, unauthorized access and audit failure.
6. Preservation of original observations and provenance.

## Verification vocabulary

Keep these concepts distinct:
- **Unverified:** received but not independently checked.
- **Corroborated:** supported by independent sources under a defined rule.
- **Operator-reviewed:** reviewed by an identified and authorized person; not cryptographic attestation.
- **Verified:** validated by a documented method that actually checks the claim.

Repeated claims from sources that share upstream data are not necessarily independent evidence.

## Next steps

Expand normalizer coverage, define temporal/freshness rules and conflict presentation, then design reviewed association. Only after per-control evidence acceptance rules and adversarial tests exist should observations influence posture assessment.
