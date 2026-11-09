"""Add principals and individually revocable API credentials.

Revision ID: 0006_identity_access
Revises: 0005_sbom_finding_intelligence
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006_identity_access"
down_revision: Union[str, None] = "0005_sbom_finding_intelligence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "principals",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("kind IN ('operator', 'service')", name="ck_principal_kind"),
        sa.CheckConstraint("status IN ('active', 'disabled')", name="ck_principal_status"),
    )
    op.create_table(
        "api_credentials",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("principal_id", sa.String(length=36), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("prefix", sa.String(length=12), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("prefix", name="uq_api_credential_prefix"),
        sa.UniqueConstraint("token_digest", name="uq_api_credential_token_digest"),
    )
    op.create_index("ix_api_credentials_principal_id", "api_credentials", ["principal_id"])


def downgrade() -> None:
    op.drop_index("ix_api_credentials_principal_id", table_name="api_credentials")
    op.drop_table("api_credentials")
    op.drop_table("principals")
