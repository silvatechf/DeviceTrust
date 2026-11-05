"""Create the initial DeviceTrust schema.

Revision ID: 0001_initial
Revises:
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("device_id", sa.String(length=64), primary_key=True),
        sa.Column("manufacturer", sa.String(length=100), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("firmware_version", sa.String(length=50), nullable=False),
        sa.Column("support_until", sa.Date(), nullable=True),
        sa.Column("security", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ts", sa.String(length=40), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("action", sa.String(length=60), nullable=False),
        sa.Column("entity", sa.String(length=120), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
    )
    op.create_table(
        "evidence_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.String(length=64), sa.ForeignKey("devices.device_id"), nullable=True),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("attribute", sa.String(length=80), nullable=False),
        sa.Column("value", sa.String(length=1000), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence", sa.String(length=10), nullable=False),
        sa.Column("verification_status", sa.String(length=16), nullable=False),
        sa.Column("evidence_reference", sa.String(length=500), nullable=True),
        sa.Column("evidence_hash", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_evidence_observations_device_id", "evidence_observations", ["device_id"])
    op.create_index("ix_evidence_observations_attribute", "evidence_observations", ["attribute"])
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.String(length=64), sa.ForeignKey("devices.device_id"), nullable=False),
        sa.Column("component", sa.String(length=200), nullable=False),
        sa.Column("version", sa.String(length=100), nullable=False),
        sa.Column("vuln_id", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("fixed_in", sa.String(length=100), nullable=True),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("justification", sa.String(length=1000), nullable=True),
        sa.UniqueConstraint("device_id", "component", "version", "vuln_id"),
    )
    op.create_index("ix_vulnerabilities_device_id", "vulnerabilities", ["device_id"])


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_device_id", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_index("ix_evidence_observations_attribute", table_name="evidence_observations")
    op.drop_index("ix_evidence_observations_device_id", table_name="evidence_observations")
    op.drop_table("evidence_observations")
    op.drop_table("audit_log")
    op.drop_table("devices")
