"""Preserve CycloneDX BOM and component references.

Revision ID: 0008_sbom_reference_preservation
Revises: 0007_sbom_finding_applicability
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008_sbom_reference_preservation"
down_revision: Union[str, None] = "0007_sbom_finding_applicability"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "sbom_imports",
        sa.Column("bom_metadata", sa.JSON(), nullable=True),
    )
    op.execute(
        sa.text(
            "UPDATE sbom_imports SET bom_metadata = '{}' "
            "WHERE bom_metadata IS NULL"
        )
    )
    with op.batch_alter_table("sbom_imports") as batch_op:
        batch_op.alter_column(
            "bom_metadata",
            existing_type=sa.JSON(),
            nullable=False,
        )

    op.add_column(
        "sbom_components",
        sa.Column("bom_ref", sa.String(length=255), nullable=True),
    )
    with op.batch_alter_table("sbom_components") as batch_op:
        batch_op.create_unique_constraint(
            "uq_sbom_component_import_bom_ref",
            ["sbom_import_id", "bom_ref"],
        )


def downgrade() -> None:
    with op.batch_alter_table("sbom_components") as batch_op:
        batch_op.drop_constraint(
            "uq_sbom_component_import_bom_ref",
            type_="unique",
        )
    op.drop_column("sbom_components", "bom_ref")
    op.drop_column("sbom_imports", "bom_metadata")
