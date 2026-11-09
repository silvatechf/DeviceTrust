"""Persist bounded evidence artifacts with server-computed digests.

Revision ID: 0013_evidence_artifacts
Revises: 0012_decision_approvals
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013_evidence_artifacts"
down_revision: Union[str, None] = "0012_decision_approvals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "evidence_artifacts",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "observation_id",
            sa.Integer(),
            sa.ForeignKey("evidence_observations.id"),
            nullable=False,
        ),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.String(length=100), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("uploaded_by", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "byte_size > 0 AND byte_size <= 5242880",
            name="ck_evidence_artifact_size",
        ),
        sa.UniqueConstraint(
            "observation_id",
            "sha256",
            "media_type",
            name="uq_evidence_artifact_observation_digest_type",
        ),
    )
    op.create_index(
        "ix_evidence_artifacts_observation_id",
        "evidence_artifacts",
        ["observation_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_evidence_artifacts_observation_id",
        table_name="evidence_artifacts",
    )
    op.drop_table("evidence_artifacts")
