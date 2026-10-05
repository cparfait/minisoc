"""incidents (F-24)

Révision : 0002_incidents
Précédente : 0001_initial
Date : 2026-10-03

Idempotente : une base convertie depuis l'ancien mécanisme (create_all) peut déjà contenir ces tables.
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_incidents"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "incidents" not in tables:
        op.create_table(
            "incidents",
            sa.Column("id", sa.BigInteger(), nullable=False),
            sa.Column("title", sa.String(length=300), nullable=False),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("category", sa.String(length=32), nullable=False, server_default="autre"),
            sa.Column("severity", sa.Integer(), nullable=False, server_default="2"),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="open"),
            sa.Column("owner", sa.String(length=64), nullable=True),
            sa.Column("created_by", sa.String(length=64), nullable=False),
            sa.Column("personal_data", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("conclusion", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_incidents_status", "incidents", ["status"])
        op.create_index("ix_incidents_created_at", "incidents", ["created_at"])
    if "incident_entries" not in tables:
        op.create_table(
            "incident_entries",
            sa.Column("id", sa.BigInteger(), nullable=False),
            sa.Column("incident_id", sa.BigInteger(), nullable=False),
            sa.Column("ts", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("actor", sa.String(length=64), nullable=False),
            sa.Column("kind", sa.String(length=16), nullable=False),
            sa.Column("detail", sa.Text(), nullable=False, server_default=""),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_incident_entries_incident_id", "incident_entries", ["incident_id"])
    columns = {c["name"] for c in inspector.get_columns("alerts")}
    if "incident_id" not in columns:
        op.add_column("alerts", sa.Column("incident_id", sa.BigInteger(), nullable=True))
        op.create_foreign_key("alerts_incident_id_fkey", "alerts", "incidents", ["incident_id"], ["id"],
                              ondelete="SET NULL")
        op.create_index("ix_alerts_incident_id", "alerts", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_alerts_incident_id", table_name="alerts")
    op.drop_constraint("alerts_incident_id_fkey", "alerts", type_="foreignkey")
    op.drop_column("alerts", "incident_id")
    op.drop_table("incident_entries")
    op.drop_table("incidents")
