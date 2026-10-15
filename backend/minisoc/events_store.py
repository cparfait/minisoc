"""Stockage des événements normalisés dans ClickHouse."""

from __future__ import annotations

import uuid
from typing import Any

import clickhouse_connect

from minisoc.config import get_settings
from minisoc.ecs import COLUMNS, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    ts               DateTime64(3, 'UTC'),
    module           LowCardinality(String),
    kind             LowCardinality(String),
    category         LowCardinality(String),
    action           LowCardinality(String),
    outcome          LowCardinality(String),
    reason           LowCardinality(String),
    severity         UInt8,
    source_ip        String,
    source_port      UInt16,
    source_country   LowCardinality(String),
    source_as        LowCardinality(String),
    destination_ip   String,
    destination_port UInt16,
    user_name        String,
    user_key         String,
    user_roles       LowCardinality(String),
    host_name        String,
    host_key         String,
    host_ip          String,
    network_service  LowCardinality(String),
    rule_name        String,
    threat_name      String,
    intel            LowCardinality(String),
    file_path        String,
    dns_query        String,
    dns_domain       LowCardinality(String),
    observer         LowCardinality(String),
    reference        String,
    message          String,
    raw              String CODEC(ZSTD(3)),
    event_id         UUID,
    ingest_ts        DateTime64(3, 'UTC') DEFAULT now64(3),
    INDEX idx_source_ip source_ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_user user_name TYPE bloom_filter GRANULARITY 4,
    INDEX idx_host host_name TYPE bloom_filter GRANULARITY 4,
    INDEX idx_user_key user_key TYPE bloom_filter GRANULARITY 4,
    INDEX idx_host_key host_key TYPE bloom_filter GRANULARITY 4,
    INDEX idx_event_id event_id TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (module, category, ts)
TTL toDateTime(ts) + INTERVAL 7 DAY RECOMPRESS CODEC(ZSTD(12)),
    toDateTime(ts) + INTERVAL 365 DAY DELETE
"""

# Évolutions de schéma appliquées au démarrage (idempotentes)
MIGRATIONS = (
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS reason LowCardinality(String) AFTER outcome",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS intel LowCardinality(String) AFTER threat_name",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS source_country LowCardinality(String) AFTER source_port",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS source_as LowCardinality(String) AFTER source_country",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS user_roles LowCardinality(String) AFTER user_name",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS dns_query String AFTER file_path",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS dns_domain LowCardinality(String) AFTER dns_query",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS user_key String AFTER user_name",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS host_key String AFTER host_name",
    "ALTER TABLE events ADD INDEX IF NOT EXISTS idx_user_key user_key TYPE bloom_filter GRANULARITY 4",
    "ALTER TABLE events ADD INDEX IF NOT EXISTS idx_host_key host_key TYPE bloom_filter GRANULARITY 4",
)

QUERY_SETTINGS = {"max_execution_time": 15}


class EventStore:
    def __init__(self, client: Any) -> None:
        self.client = client

    @classmethod
    async def connect(cls) -> EventStore:
        s = get_settings()
        client = await clickhouse_connect.get_async_client(
            host=s.clickhouse_host,
            port=s.clickhouse_port,
            username=s.clickhouse_user,
            password=s.clickhouse_password,
            database=s.clickhouse_database,
        )
        return cls(client)

    async def ensure_schema(self) -> None:
        await self.client.command(SCHEMA)
        for statement in MIGRATIONS:
            await self.client.command(statement)

    async def insert(self, events: list[Event]) -> None:
        if not events:
            return
        rows = []
        for ev in events:
            row = ev.to_row()
            row["event_id"] = uuid.UUID(ev.event_id)
            rows.append([row[c] for c in COLUMNS])
        await self.client.insert("events", rows, column_names=list(COLUMNS))

    async def set_retention(self, days: int) -> None:
        """Recompression après 7 jours (archive compacte), suppression après `days` jours."""
        await self.client.command(
            f"ALTER TABLE events MODIFY TTL toDateTime(ts) + INTERVAL 7 DAY RECOMPRESS CODEC(ZSTD(12)), "
            f"toDateTime(ts) + INTERVAL {int(days)} DAY DELETE"
        )

    async def query(self, sql: str, params: dict | None = None) -> list[dict]:
        result = await self.client.query(sql, parameters=params or {}, settings=QUERY_SETTINGS)
        return list(result.named_results())

    async def by_ids(self, event_ids: list[str], limit: int = 50) -> list[dict]:
        ids = [i for i in event_ids if _is_uuid(i)][:limit]
        if not ids:
            return []
        return await self.query(
            "SELECT * FROM events WHERE event_id IN {ids:Array(UUID)} ORDER BY ts DESC LIMIT {n:UInt32}",
            {"ids": ids, "n": limit},
        )

    async def close(self) -> None:
        close = getattr(self.client, "close", None)
        if close:
            result = close()
            if hasattr(result, "__await__"):
                await result


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False
