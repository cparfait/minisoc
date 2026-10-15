"""serveurs autorisés à envoyer leurs rapports Trivy (jeton propre à chaque serveur)

Révision : 0008_trivy_sources
Précédente : 0007_user_preferences
Date : 2026-10-14
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0008_trivy_sources"
down_revision = "0007_user_preferences"
branch_labels = None
depends_on = None

NOW = sa.text("now()")


def upgrade() -> None:
    if "trivy_sources" in set(sa.inspect(op.get_bind()).get_table_names()):
        return
    op.create_table(
        "trivy_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("allowed_ips", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=NOW),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("last_ip", sa.String(64), nullable=False, server_default=""),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_table("trivy_sources")
