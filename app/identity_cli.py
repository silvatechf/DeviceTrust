import argparse
from datetime import timedelta
from pathlib import Path

from . import audit, decision_signatures, identity
from .db import SessionLocal, utcnow


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline DeviceTrust principal and API credential administration."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create-principal", help="Create a principal and show its API token once.")
    create.add_argument("--name", required=True)
    create.add_argument("--kind", choices=("operator", "service"), required=True)
    create.add_argument("--scope", action="append", required=True, dest="scopes")
    create.add_argument("--expires-in-days", type=int, default=90)

    issue = commands.add_parser("issue-credential", help="Issue an additional or replacement credential.")
    issue.add_argument("--principal-id", required=True)
    issue.add_argument("--scope", action="append", required=True, dest="scopes")
    issue.add_argument("--expires-in-days", type=int, default=90)

    revoke = commands.add_parser("revoke-credential", help="Revoke an API credential.")
    revoke.add_argument("--credential-id", required=True)

    disable = commands.add_parser("disable-principal", help="Disable a principal and all its credentials.")
    disable.add_argument("--principal-id", required=True)

    register_key = commands.add_parser(
        "register-signing-key",
        help="Register an operator Ed25519 public key for signing or approval; private keys are never imported.",
    )
    register_key.add_argument("--principal-id", required=True)
    register_key.add_argument("--public-key-file", required=True)
    register_key.add_argument(
        "--purpose",
        choices=("decision-signing", "decision-approval"),
        default="decision-signing",
    )
    register_key.add_argument("--expires-in-days", type=int, default=365)

    revoke_key = commands.add_parser("revoke-signing-key", help="Revoke an operator signing public key.")
    revoke_key.add_argument("--key-id", required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    with SessionLocal() as db:
        if args.command == "create-principal":
            if not 1 <= args.expires_in_days <= 365:
                raise SystemExit("--expires-in-days must be between 1 and 365")
            expires_at = utcnow() + timedelta(days=args.expires_in_days)
            try:
                principal, credential, raw_token = identity.create_principal(
                    db,
                    name=args.name,
                    kind=args.kind,
                    scopes=set(args.scopes),
                    expires_at=expires_at,
                )
            except identity.IdentityConfigurationError as exc:
                raise SystemExit(str(exc)) from None
            audit.record(
                db,
                "offline-admin",
                "identity.principal_create",
                principal.id,
                {
                    "principal_kind": principal.kind,
                    "credential_id": credential.id,
                    "scopes": credential.scopes,
                    "expires_at": credential.expires_at.isoformat(),
                },
            )
            db.commit()
            print(f"Principal ID: {principal.id}")
            print(f"Credential ID: {credential.id}")
            print(f"Expires at: {credential.expires_at.isoformat()}")
            print("API token (shown once; store it securely):")
            print(raw_token)
            return

        if args.command == "issue-credential":
            if not 1 <= args.expires_in_days <= 365:
                raise SystemExit("--expires-in-days must be between 1 and 365")
            try:
                credential, raw_token = identity.issue_credential(
                    db,
                    principal_id=args.principal_id,
                    scopes=set(args.scopes),
                    expires_at=utcnow() + timedelta(days=args.expires_in_days),
                )
            except identity.IdentityConfigurationError as exc:
                raise SystemExit(str(exc)) from None
            audit.record(
                db,
                "offline-admin",
                "identity.credential_create",
                credential.id,
                {
                    "principal_id": credential.principal_id,
                    "credential_id": credential.id,
                    "scopes": credential.scopes,
                    "expires_at": credential.expires_at.isoformat(),
                },
            )
            db.commit()
            print(f"Credential ID: {credential.id}")
            print(f"Expires at: {credential.expires_at.isoformat()}")
            print("API token (shown once; store it securely):")
            print(raw_token)
            return

        if args.command == "revoke-credential":
            identity.revoke_credential(db, args.credential_id)
            audit.record(
                db,
                "offline-admin",
                "identity.credential_revoke",
                args.credential_id,
                {"credential_id": args.credential_id},
            )
            db.commit()
            print(f"Credential revoked: {args.credential_id}")
            return

        if args.command == "register-signing-key":
            if not 1 <= args.expires_in_days <= 3650:
                raise SystemExit("--expires-in-days must be between 1 and 3650")
            try:
                public_key_pem = Path(args.public_key_file).read_bytes()
                key = decision_signatures.register_public_key(
                    db,
                    principal_id=args.principal_id,
                    public_key_pem=public_key_pem,
                    purpose=args.purpose,
                    expires_at=utcnow() + timedelta(days=args.expires_in_days),
                )
            except (OSError, LookupError, PermissionError, ValueError) as exc:
                db.rollback()
                raise SystemExit(str(exc)) from None
            db.commit()
            print(f"Signing key ID: {key.id}")
            print(f"Principal ID: {key.principal_id}")
            print(f"Purpose: {key.purpose}")
            print(f"Fingerprint (SHA-256): {key.fingerprint}")
            print(f"Expires at: {key.expires_at.isoformat() if key.expires_at else 'never'}")
            return

        if args.command == "revoke-signing-key":
            try:
                key = decision_signatures.revoke_public_key(db, args.key_id)
            except LookupError as exc:
                db.rollback()
                raise SystemExit(str(exc)) from None
            db.commit()
            print(f"Signing key revoked: {key.id}")
            print(f"Fingerprint (SHA-256): {key.fingerprint}")
            return

        if args.command == "disable-principal":
            identity.disable_principal(db, args.principal_id)
            audit.record(
                db,
                "offline-admin",
                "identity.principal_disable",
                args.principal_id,
                {"principal_id": args.principal_id},
            )
            db.commit()
            print(f"Principal disabled: {args.principal_id}")


if __name__ == "__main__":
    main()
