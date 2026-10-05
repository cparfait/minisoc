"""inventaire : machine exposée à Internet (exposition réelle)

Révision : 0005_asset_exposure
Précédente : 0004_siem
Date : 2026-10-04
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_asset_exposure"
down_revision = "0004_siem"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("assets")}
    if "internet_exposed" not in columns:
        op.add_column("assets", sa.Column("internet_exposed", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("assets", "internet_exposed")
