"""Add versioned SBOM assessment history.

Revision ID: 0004_versioned_sbom_assessments
Revises: 0003_audit_chain_state
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_versioned_sbom_assessments"
down_revision: Union[str, None] = "0003_audit_chain_state"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sbom_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("sbom_import_id", sa.Integer(), sa.ForeignKey("sbom_imports.id"), nullable=False),
        sa.Column("request_key_hash", sa.String(length=64), nullable=False),
        sa.Column("source_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("component_count", sa.Integer(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("enrichment_metadata", sa.JSON(), nullable=False),
        sa.UniqueConstraint(
            "sbom_import_id",
            "request_key_hash",
            name="uq_sbom_assessment_import_request",
        ),
        sa.CheckConstraint(
            "status IN ('disabled', 'complete', 'incomplete')",
            name="ck_sbom_assessment_status",
        ),
    )
    op.create_index(
        "ix_sbom_assessments_sbom_import_id",
        "sbom_assessments",
        ["sbom_import_id"],
    )
    op.create_table(
        "sbom_assessment_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("sbom_assessments.id"), nullable=False),
        sa.Column("sbom_component_id", sa.Integer(), sa.ForeignKey("sbom_components.id"), nullable=False),
        sa.Column("vuln_id", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("fixed_in", sa.String(length=100), nullable=True),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.UniqueConstraint(
            "assessment_id",
            "sbom_component_id",
            "vuln_id",
            "source",
            name="uq_sbom_assessment_finding_identity",
        ),
    )
    op.create_index(
        "ix_sbom_assessment_findings_assessment_id",
        "sbom_assessment_findings",
        ["assessment_id"],
    )
    op.create_index(
        "ix_sbom_assessment_findings_sbom_component_id",
        "sbom_assessment_findings",
        ["sbom_component_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_sbom_assessment_findings_sbom_component_id",
        table_name="sbom_assessment_findings",
    )
    op.drop_index(
        "ix_sbom_assessment_findings_assessment_id",
        table_name="sbom_assessment_findings",
    )
    op.drop_table("sbom_assessment_findings")
    op.drop_index(
        "ix_sbom_assessments_sbom_import_id",
        table_name="sbom_assessments",
    )
    op.drop_table("sbom_assessments")
