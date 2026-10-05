"""fiches des détections d'outils : catégorie et sévérité recalibrée

Révision : 0003_detection_profiles
Précédente : 0002_incidents
Date : 2026-10-03
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_detection_profiles"
down_revision = "0002_incidents"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "detection_profiles" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "detection_profiles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("module", sa.String(length=64), nullable=False),
        sa.Column("detection", sa.String(length=256), nullable=False),
        sa.Column("category", sa.String(length=16), nullable=False, server_default="threat"),
        sa.Column("severity", sa.Integer(), nullable=True),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("author", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ux_detection_profiles", "detection_profiles", ["module", "detection"], unique=True)


def downgrade() -> None:
    op.drop_index("ux_detection_profiles", table_name="detection_profiles")
    op.drop_table("detection_profiles")
