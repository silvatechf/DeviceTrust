"""Add append-only independent decision approvals.

Revision ID: 0012_decision_approvals
Revises: 0011_approval_key_purpose
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012_decision_approvals"
down_revision: Union[str, None] = "0011_approval_key_purpose"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "decision_approvals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "decision_id",
            sa.Integer(),
            sa.ForeignKey("vulnerability_decisions.id"),
            nullable=False,
        ),
        sa.Column(
            "signing_key_id",
            sa.String(length=36),
            sa.ForeignKey("signing_keys.id"),
            nullable=False,
        ),
        sa.Column(
            "principal_id",
            sa.String(length=36),
            sa.ForeignKey("principals.id"),
            nullable=False,
        ),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("envelope_version", sa.String(length=64), nullable=False),
        sa.Column("decision_envelope_sha256", sa.String(length=64), nullable=False),
        sa.Column("envelope_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature_b64", sa.String(length=128), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "decision_id",
            "signing_key_id",
            name="uq_decision_approval_decision_key",
        ),
    )
    op.create_index(
        "ix_decision_approvals_decision_id",
        "decision_approvals",
        ["decision_id"],
    )
    op.create_index(
        "ix_decision_approvals_signing_key_id",
        "decision_approvals",
        ["signing_key_id"],
    )
    op.create_index(
        "ix_decision_approvals_principal_id",
        "decision_approvals",
        ["principal_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_decision_approvals_principal_id", table_name="decision_approvals")
    op.drop_index("ix_decision_approvals_signing_key_id", table_name="decision_approvals")
    op.drop_index("ix_decision_approvals_decision_id", table_name="decision_approvals")
    op.drop_table("decision_approvals")
