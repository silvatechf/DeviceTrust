## Change summary

<!-- Describe the coherent outcome and why it matters. -->

## Scope and acceptance

- [ ] The change has a clear, bounded purpose.
- [ ] Acceptance criteria are testable.
- [ ] Out-of-scope work is identified where relevant.

## Validation evidence

<!-- Include exact commands and results. Link CI runs where useful. Do not claim checks that were not run. -->

- Tests:
- Static/security checks:
- Database/migration checks:
- Manual checks:

## Security, privacy and data integrity

- [ ] Authentication and authorization boundaries were reviewed.
- [ ] Untrusted input, secrets and sensitive data handling were reviewed.
- [ ] Auditability, provenance and failure behavior were considered.
- [ ] No security-sensitive behavior is silently downgraded on failure.

## Documentation and compatibility

- [ ] README or relevant technical documentation updated.
- [ ] Threat model, security controls or prototype limitations updated if affected.
- [ ] Migration and rollback implications documented if schema changes.
- [ ] Backward compatibility and API contract changes described.

## Risks and known limitations

<!-- Be explicit about residual risks, assumptions and follow-up work. -->

## Merge readiness

- [ ] CI is green on the latest PR head.
- [ ] All review feedback is resolved.
- [ ] This PR can be represented by one coherent squash commit.
- [ ] No direct changes to protected branches.
