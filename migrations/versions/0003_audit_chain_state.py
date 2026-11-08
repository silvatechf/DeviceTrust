"""Add a transactional singleton lock for audit-chain writers.

Revision ID: 0003_audit_chain_state
Revises: 0002_persistent_sbom
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_audit_chain_state"
down_revision: Union[str, None] = "0002_persistent_sbom"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_chain_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("version", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.CheckConstraint("id = 1", name="ck_audit_chain_state_singleton"),
    )
    op.execute(
        sa.text("INSERT INTO audit_chain_state (id, version) VALUES (1, 0)")
    )


def downgrade() -> None:
    op.drop_table("audit_chain_state")
