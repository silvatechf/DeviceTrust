"""Add persistent product and SBOM domain tables.

Revision ID: 0002_persistent_sbom
Revises: 0001_initial
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_persistent_sbom"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "products",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("manufacturer", sa.String(length=200), nullable=False),
        sa.Column("product_name", sa.String(length=200), nullable=False),
        sa.Column("external_reference", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "product_releases",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id"), nullable=False),
        sa.Column("version", sa.String(length=100), nullable=False),
        sa.Column("hardware_revision", sa.String(length=100), nullable=True),
        sa.Column("release_reference", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_product_releases_product_id", "product_releases", ["product_id"])
    op.create_table(
        "sbom_imports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("product_release_id", sa.Integer(), sa.ForeignKey("product_releases.id"), nullable=False),
        sa.Column("format", sa.String(length=32), nullable=False),
        sa.Column("spec_version", sa.String(length=20), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_reference", sa.String(length=500), nullable=True),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("parser_version", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("component_count", sa.Integer(), nullable=False),
        sa.Column("validation_summary", sa.JSON(), nullable=False),
        sa.UniqueConstraint(
            "product_release_id",
            "format",
            "content_sha256",
            name="uq_sbom_import_release_format_digest",
        ),
    )
    op.create_index("ix_sbom_imports_product_release_id", "sbom_imports", ["product_release_id"])
    op.create_table(
        "sbom_components",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("sbom_import_id", sa.Integer(), sa.ForeignKey("sbom_imports.id"), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("version", sa.String(length=100), nullable=False),
        sa.Column("purl", sa.String(length=512), nullable=True),
        sa.UniqueConstraint("sbom_import_id", "ordinal", name="uq_sbom_component_import_ordinal"),
    )
    op.create_index("ix_sbom_components_sbom_import_id", "sbom_components", ["sbom_import_id"])
    op.create_table(
        "product_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("sbom_component_id", sa.Integer(), sa.ForeignKey("sbom_components.id"), nullable=False),
        sa.Column("vuln_id", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("fixed_in", sa.String(length=100), nullable=True),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("justification", sa.String(length=1000), nullable=True),
        sa.UniqueConstraint(
            "sbom_component_id",
            "vuln_id",
            "source",
            name="uq_product_finding_component_vuln_source",
        ),
    )
    op.create_index("ix_product_findings_sbom_component_id", "product_findings", ["sbom_component_id"])


def downgrade() -> None:
    op.drop_index("ix_product_findings_sbom_component_id", table_name="product_findings")
    op.drop_table("product_findings")
    op.drop_index("ix_sbom_components_sbom_import_id", table_name="sbom_components")
    op.drop_table("sbom_components")
    op.drop_index("ix_sbom_imports_product_release_id", table_name="sbom_imports")
    op.drop_table("sbom_imports")
    op.drop_index("ix_product_releases_product_id", table_name="product_releases")
    op.drop_table("product_releases")
    op.drop_table("products")
