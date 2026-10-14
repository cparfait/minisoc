"""préférences d'affichage par utilisateur (tableau de bord configurable, écran mural)

Révision : 0007_user_preferences
Précédente : 0006_alert_followup
Date : 2026-10-08
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0007_user_preferences"
down_revision = "0006_alert_followup"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("users")}
    if "preferences" not in columns:
        op.add_column("users", sa.Column("preferences", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")))


def downgrade() -> None:
    op.drop_column("users", "preferences")
