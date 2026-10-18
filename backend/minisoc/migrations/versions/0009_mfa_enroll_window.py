"""fenêtre d'enrôlement MFA ouverte par un administrateur (le mot de passe seul ne suffit plus)

Révision : 0009_mfa_enroll_window
Précédente : 0008_trivy_sources
Date : 2026-10-18
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_mfa_enroll_window"
down_revision = "0008_trivy_sources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("users")}
    if "mfa_enroll_until" not in columns:
        op.add_column("users", sa.Column("mfa_enroll_until", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "mfa_enroll_until")
