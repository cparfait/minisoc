"""Connexion PostgreSQL (SQLAlchemy asynchrone) et migrations du schéma (Alembic)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from minisoc.config import get_settings
from minisoc.models import Base

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker | None = None

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
BASELINE = "0001_initial"
MIGRATION_LOCK = 7366823

# Colonnes ajoutées avant l'adoption d'Alembic : appliquées une fois sur une base antérieure, puis la base est
# rattachée à la migration initiale (« stamp »), qui décrit exactement ce schéma.
LEGACY_MIGRATIONS = (
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source VARCHAR(8) NOT NULL DEFAULT 'local'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(256) NOT NULL DEFAULT ''",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(256) NOT NULL DEFAULT ''",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ",
    "ALTER TABLE users ALTER COLUMN password_hash SET DEFAULT ''",
    "ALTER TABLE users ALTER COLUMN totp_secret_enc SET DEFAULT ''",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS reminded_at TIMESTAMPTZ",
)


def engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(get_settings().database_url, pool_pre_ping=True, pool_size=10)
    return _engine


def sessionmaker() -> async_sessionmaker:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(engine(), expire_on_commit=False)
    return _sessionmaker


def alembic_config(connection=None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def _upgrade(sync_conn) -> None:
    tables = set(inspect(sync_conn).get_table_names())
    if "alembic_version" not in tables and "users" in tables:
        Base.metadata.create_all(sync_conn)  # tables apparues entre-temps (n'altère pas l'existant)
        for statement in LEGACY_MIGRATIONS:
            sync_conn.execute(text(statement))
        command.stamp(alembic_config(sync_conn), BASELINE)
    command.upgrade(alembic_config(sync_conn), "head")


async def init_db() -> None:
    """Applique les migrations manquantes. Le verrou évite une course entre l'API et le worker au démarrage."""
    async with engine().begin() as conn:
        await conn.execute(text(f"SELECT pg_advisory_xact_lock({MIGRATION_LOCK})"))
        await conn.run_sync(_upgrade)
