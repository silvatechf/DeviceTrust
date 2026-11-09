"""Persist source-aware applicability signals on assessment findings.

Revision ID: 0007_sbom_finding_applicability
Revises: 0006_identity_access
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007_sbom_finding_applicability"
down_revision: Union[str, None] = "0006_identity_access"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "sbom_assessment_findings",
        sa.Column("applicability", sa.JSON(), nullable=True),
    )
    op.execute(
        sa.text(
            "UPDATE sbom_assessment_findings "
            "SET applicability = '{}' WHERE applicability IS NULL"
        )
    )
    with op.batch_alter_table("sbom_assessment_findings") as batch_op:
        batch_op.alter_column(
            "applicability",
            existing_type=sa.JSON(),
            nullable=False,
        )


def downgrade() -> None:
    op.drop_column("sbom_assessment_findings", "applicability")
