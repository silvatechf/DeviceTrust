"""Allow dedicated public keys for independent decision approvals.

Revision ID: 0011_approval_key_purpose
Revises: 0010_decision_signatures
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011_approval_key_purpose"
down_revision: Union[str, None] = "0010_decision_signatures"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("signing_keys") as batch:
        batch.drop_constraint("ck_signing_key_purpose", type_="check")
        batch.create_check_constraint(
            "ck_signing_key_purpose",
            "purpose IN ('decision-signing', 'decision-approval')",
        )


def downgrade() -> None:
    approval_key_exists = op.get_bind().execute(
        sa.text("SELECT 1 FROM signing_keys WHERE purpose = 'decision-approval' LIMIT 1")
    ).first()
    if approval_key_exists is not None:
        raise RuntimeError(
            "Cannot downgrade approval key purposes while decision-approval keys exist; "
            "revoke and remove those keys through an explicit data-retention procedure first."
        )
    with op.batch_alter_table("signing_keys") as batch:
        batch.drop_constraint("ck_signing_key_purpose", type_="check")
        batch.create_check_constraint(
            "ck_signing_key_purpose",
            "purpose IN ('decision-signing')",
        )
