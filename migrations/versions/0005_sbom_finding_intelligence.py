"""Persist provider intelligence on versioned SBOM findings.

Revision ID: 0005_sbom_finding_intelligence
Revises: 0004_versioned_sbom_assessments
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005_sbom_finding_intelligence"
down_revision: Union[str, None] = "0004_versioned_sbom_assessments"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "sbom_assessment_findings",
        sa.Column("intelligence", sa.JSON(), nullable=True),
    )
    op.execute(
        sa.text(
            "UPDATE sbom_assessment_findings "
            "SET intelligence = '{}' WHERE intelligence IS NULL"
        )
    )
    # Batch mode recreates the table on SQLite (which does not support
    # ALTER COLUMN) and emits a normal ALTER on PostgreSQL.
    with op.batch_alter_table("sbom_assessment_findings") as batch_op:
        batch_op.alter_column(
            "intelligence",
            existing_type=sa.JSON(),
            nullable=False,
        )


def downgrade() -> None:
    op.drop_column("sbom_assessment_findings", "intelligence")
