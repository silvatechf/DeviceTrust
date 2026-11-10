"""Bind immutable evidence manifests to exact vulnerability decisions.

Revision ID: 0014_decision_evidence_manifests
Revises: 0013_evidence_artifacts
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014_decision_evidence_manifests"
down_revision: Union[str, None] = "0013_evidence_artifacts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "decision_evidence_manifests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "decision_id",
            sa.Integer(),
            sa.ForeignKey("vulnerability_decisions.id"),
            nullable=False,
        ),
        sa.Column("manifest_version", sa.String(length=80), nullable=False),
        sa.Column("manifest_payload", sa.JSON(), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("artifact_ids", sa.JSON(), nullable=False),
        sa.Column(
            "created_by",
            sa.String(length=36),
            sa.ForeignKey("principals.id"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "manifest_version = 'devicetrust.decision-evidence-manifest.v1'",
            name="ck_decision_evidence_manifest_version",
        ),
        sa.UniqueConstraint(
            "decision_id",
            name="uq_decision_evidence_manifest_decision",
        ),
    )
    op.create_index(
        "ix_decision_evidence_manifests_decision_id",
        "decision_evidence_manifests",
        ["decision_id"],
    )
    op.create_index(
        "ix_decision_evidence_manifests_created_by",
        "decision_evidence_manifests",
        ["created_by"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_decision_evidence_manifests_created_by",
        table_name="decision_evidence_manifests",
    )
    op.drop_index(
        "ix_decision_evidence_manifests_decision_id",
        table_name="decision_evidence_manifests",
    )
    op.drop_table("decision_evidence_manifests")
