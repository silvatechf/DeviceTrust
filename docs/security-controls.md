# Security Controls and Evidence Model

## Evidence states

- `compliant`: supplied evidence meets the modeled criterion.
- `partial`: evidence demonstrates incomplete implementation.
- `non_compliant`: evidence demonstrates a control failure.
- `unverified`: evidence is absent or insufficient.

A control must never become compliant solely because a field was omitted.

## Internet exposure

Internet exposure is modeled separately from ordinary open interfaces:

- `internet_exposed`: nullable boolean; `null` means unknown.
- `management_interfaces`: declared management plane, protocol, internet exposure and authentication requirement.

An internet-exposed management interface is a high-risk finding even when authentication is required. Authentication does not remove the attack surface. The prototype accepts declared evidence; it does not independently discover public reachability. Evidence provenance and observation timestamps remain planned.

## Lifecycle

Track product/model and firmware lifecycle independently:
- `support_status`: supported, end_of_life, unknown.
- `support_until`: vendor-published date, when known.
- `eol_announced_at`: vendor announcement date.
- `lifecycle_source`: vendor advisory or verified source.

Do not infer EOL from missing support metadata.

## Audit guarantees

The current hash chain detects modifications that do not recompute all following hashes. It is not immutable storage and cannot stop a privileged attacker from rewriting the database and chain. Stronger assurance requires external signed checkpoints, independently controlled storage or WORM retention.
