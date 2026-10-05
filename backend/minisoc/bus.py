"""File d'attente Redis Streams entre la réception et le traitement des messages."""

from __future__ import annotations

from datetime import datetime, timezone

import redis.asyncio as aioredis

from minisoc.config import get_settings

STREAM_RAW = "minisoc:raw"
GROUP_PIPELINE = "pipeline"
SOURCES_KEY = "minisoc:sources:last_seen"  # hash module -> horodatage ISO du dernier événement
WORKER_HEARTBEAT_KEY = "minisoc:worker:heartbeat"
MAX_STREAM_LEN = 5_000_000  # borne approximative de la file (≈ tampon de plusieurs heures en pointe)


def connect() -> aioredis.Redis:
    return aioredis.from_url(get_settings().redis_url, decode_responses=True)


async def publish(redis: aioredis.Redis, kind: str, payloads: list[str]) -> int:
    if not payloads:
        return 0
    pipe = redis.pipeline(transaction=False)
    for payload in payloads:
        pipe.xadd(STREAM_RAW, {"kind": kind, "payload": payload}, maxlen=MAX_STREAM_LEN, approximate=True)
    await pipe.execute()
    return len(payloads)


async def ensure_group(redis: aioredis.Redis) -> None:
    try:
        await redis.xgroup_create(STREAM_RAW, GROUP_PIPELINE, id="0", mkstream=True)
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def mark_seen(redis: aioredis.Redis, modules: dict[str, datetime]) -> None:
    """Dernière activité de chaque source, sans jamais reculer : un import d'historique (événements datés du
    passé) ne doit pas faire croire qu'une source s'est tue."""
    if not modules:
        return
    names = list(modules)
    current = dict(zip(names, await redis.hmget(SOURCES_KEY, names), strict=True))
    newer = {}
    for module, ts in modules.items():
        try:
            previous = datetime.fromisoformat(current[module]) if current[module] else None
        except ValueError:
            previous = None
        if previous is None or ts > previous:
            newer[module] = ts.isoformat()
    if newer:
        await redis.hset(SOURCES_KEY, mapping=newer)


async def heartbeat(redis: aioredis.Redis, module: str) -> None:
    await mark_seen(redis, {module: datetime.now(timezone.utc)})


async def sources_last_seen(redis: aioredis.Redis) -> dict[str, datetime]:
    raw = await redis.hgetall(SOURCES_KEY)
    out = {}
    for module, value in raw.items():
        try:
            out[module] = datetime.fromisoformat(value)
        except ValueError:
            continue
    return out


async def queue_state(redis: aioredis.Redis) -> dict:
    """Retard du traitement : messages en attente de lecture (lag) et lus mais non acquittés (pending)."""
    try:
        groups = await redis.xinfo_groups(STREAM_RAW)
    except aioredis.ResponseError:
        return {"lag": 0, "pending": 0}
    group = next((g for g in groups if g.get("name") == GROUP_PIPELINE), {})
    return {"lag": int(group.get("lag") or 0), "pending": int(group.get("pending") or 0)}
