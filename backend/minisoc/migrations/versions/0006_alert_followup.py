"""suivi des alertes : date de prise en charge (échéances), statut « en attente »

Révision : 0006_alert_followup
Précédente : 0005_asset_exposure
Date : 2026-10-04
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_alert_followup"
down_revision = "0005_asset_exposure"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("alerts")}
    if "acknowledged_at" not in columns:
        op.add_column("alerts", sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True))
        # Alertes déjà prises en charge (statut avancé ou personne assignée) : date de la dernière modification
        op.execute("UPDATE alerts SET acknowledged_at = updated_at WHERE status <> 'new' OR assignee IS NOT NULL")


def downgrade() -> None:
    op.drop_column("alerts", "acknowledged_at")
