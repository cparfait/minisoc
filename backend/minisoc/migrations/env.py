"""Environnement Alembic : migrations du schéma PostgreSQL (alertes, comptes, paramètres, audit…).

Appelé soit par init_db() avec une connexion déjà ouverte (démarrage de l'API et du worker), soit en ligne de
commande : docker compose exec api python -m minisoc.cli db-revision -m "message" (développement).
"""

import asyncio

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from minisoc.config import get_settings
from minisoc.models import Base

config = context.config
target_metadata = Base.metadata


def run_with(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_async() -> None:
    engine = create_async_engine(get_settings().database_url)
    async with engine.begin() as conn:
        await conn.run_sync(run_with)
    await engine.dispose()


connection = config.attributes.get("connection")
if connection is not None:
    run_with(connection)
else:
    asyncio.run(run_async())
