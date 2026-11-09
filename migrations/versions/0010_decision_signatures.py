"""Add Ed25519 public keys and immutable decision signatures.

Revision ID: 0010_decision_signatures
Revises: 0009_vulnerability_decisions
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010_decision_signatures"
down_revision: Union[str, None] = "0009_vulnerability_decisions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "signing_keys",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("principal_id", sa.String(length=36), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("algorithm", sa.String(length=16), nullable=False),
        sa.Column("public_key_pem", sa.String(length=512), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("fingerprint", name="uq_signing_key_fingerprint"),
        sa.CheckConstraint("purpose IN ('decision-signing')", name="ck_signing_key_purpose"),
        sa.CheckConstraint("algorithm = 'Ed25519'", name="ck_signing_key_algorithm"),
    )
    op.create_index("ix_signing_keys_principal_id", "signing_keys", ["principal_id"])

    op.create_table(
        "signed_decisions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "decision_id",
            sa.Integer(),
            sa.ForeignKey("vulnerability_decisions.id"),
            nullable=False,
        ),
        sa.Column("signing_key_id", sa.String(length=36), sa.ForeignKey("signing_keys.id"), nullable=False),
        sa.Column("principal_id", sa.String(length=36), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("envelope_version", sa.String(length=64), nullable=False),
        sa.Column("envelope_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature_b64", sa.String(length=128), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("decision_id", name="uq_signed_decision_decision"),
    )
    op.create_index("ix_signed_decisions_decision_id", "signed_decisions", ["decision_id"])
    op.create_index("ix_signed_decisions_signing_key_id", "signed_decisions", ["signing_key_id"])
    op.create_index("ix_signed_decisions_principal_id", "signed_decisions", ["principal_id"])


def downgrade() -> None:
    op.drop_index("ix_signed_decisions_principal_id", table_name="signed_decisions")
    op.drop_index("ix_signed_decisions_signing_key_id", table_name="signed_decisions")
    op.drop_index("ix_signed_decisions_decision_id", table_name="signed_decisions")
    op.drop_table("signed_decisions")
    op.drop_index("ix_signing_keys_principal_id", table_name="signing_keys")
    op.drop_table("signing_keys")
