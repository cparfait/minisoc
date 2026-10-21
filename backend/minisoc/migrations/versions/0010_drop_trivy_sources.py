"""Trivy retiré du Mini-SOC : table des serveurs autorisés à envoyer leurs rapports supprimée

Révision : 0010_drop_trivy_sources
Précédente : 0009_mfa_enroll_window
Date : 2026-10-21
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0010_drop_trivy_sources"
down_revision = "0009_mfa_enroll_window"
branch_labels = None
depends_on = None

NOW = sa.text("now()")


def upgrade() -> None:
    if "trivy_sources" in set(sa.inspect(op.get_bind()).get_table_names()):
        op.drop_table("trivy_sources")


def downgrade() -> None:
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
