"""briques SIEM : recherches enregistrées, règles importées, inventaire, IOC, archives scellées

Révision : 0004_siem
Précédente : 0003_detection_profiles
Date : 2026-10-03
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0004_siem"
down_revision = "0003_detection_profiles"
branch_labels = None
depends_on = None

NOW = sa.text("now()")


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "saved_searches" not in tables:
        op.create_table(
            "saved_searches",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("query", sa.Text(), nullable=False),
            sa.Column("period", sa.String(16), nullable=False, server_default="24h"),
            sa.Column("owner", sa.String(64), nullable=False),
            sa.Column("shared", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=NOW),
        )
        op.create_index("ix_saved_searches_owner", "saved_searches", ["owner"])
    if "custom_rules" not in tables:
        op.create_table(
            "custom_rules",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("rule_id", sa.String(64), nullable=False, unique=True),
            sa.Column("source", sa.String(16), nullable=False, server_default="sigma"),
            sa.Column("original", sa.Text(), nullable=False, server_default=""),
            sa.Column("definition", JSONB(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("author", sa.String(64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=NOW),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=NOW),
        )
    if "assets" not in tables:
        op.create_table(
            "assets",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("kind", sa.String(16), nullable=False),
            sa.Column("name", sa.String(256), nullable=False),
            sa.Column("display_name", sa.String(256), nullable=False),
            sa.Column("criticality", sa.String(16), nullable=False, server_default="normal"),
            sa.Column("owner", sa.String(256), nullable=False, server_default=""),
            sa.Column("service", sa.String(256), nullable=False, server_default=""),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("asset_type", sa.String(32), nullable=False, server_default=""),
            sa.Column("source", sa.String(32), nullable=False, server_default="manual"),
            sa.Column("reviewed", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=NOW),
        )
        op.create_index("ux_assets_kind_name", "assets", ["kind", "name"], unique=True)
    if "iocs" not in tables:
        op.create_table(
            "iocs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("type", sa.String(16), nullable=False),
            sa.Column("value", sa.String(512), nullable=False),
            sa.Column("source", sa.String(128), nullable=False, server_default="manuel"),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("author", sa.String(64), nullable=False, server_default=""),
            sa.Column("hits", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_hit", sa.DateTime(timezone=True), nullable=True),
            sa.Column("hunted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=NOW),
        )
        op.create_index("ux_iocs_type_value", "iocs", ["type", "value"], unique=True)
    if "ioc_feeds" not in tables:
        op.create_table(
            "ioc_feeds",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(128), nullable=False, unique=True),
            sa.Column("url", sa.String(512), nullable=False),
            sa.Column("type", sa.String(16), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error", sa.Text(), nullable=False, server_default=""),
        )
    if "archives" not in tables:
        op.create_table(
            "archives",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("day", sa.String(10), nullable=False, unique=True),
            sa.Column("path", sa.String(256), nullable=False),
            sa.Column("events", sa.Integer(), nullable=False),
            sa.Column("size", sa.BigInteger(), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("prev_hash", sa.String(64), nullable=False),
            sa.Column("chain_hash", sa.String(64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=NOW),
        )


def downgrade() -> None:
    for table in ("archives", "ioc_feeds", "iocs", "assets", "custom_rules", "saved_searches"):
        op.drop_table(table)
