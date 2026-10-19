"""Archives scellées des événements : un fichier par jour, empreinte SHA-256 chaînée à la veille.

Chaque nuit, les événements de la veille (UTC) sont écrits en JSON (une ligne par événement), compressés, puis
scellés : `chain_hash = SHA-256(empreinte précédente | jour | empreinte du fichier | nombre d'événements)`.
Modifier, supprimer ou réécrire une archive casse la chaîne. La dernière empreinte de chaîne part chaque jour dans
le résumé par e-mail : une réécriture complète de la chaîne serait donc elle aussi détectable.

Un manifeste (`manifest.jsonl`) est écrit à côté des fichiers : la vérification est possible sans le Mini-SOC
(`sha256sum` et le calcul ci-dessus). Les événements reçus après le scellement d'un jour (import d'historique)
ne figurent pas dans son archive.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.models import Archive

log = logging.getLogger(__name__)

GENESIS = "0" * 64
BATCH = 50_000
MAX_CATCH_UP = 31  # jours rattrapés au plus par passage
# Lisibles par le compte minisoc-backup de la VM (volume présenté en lecture seule dans /var/backups/minisoc/archives),
# quel que soit le umask du conteneur ; les droits ne changent pas l'empreinte
READABLE = 0o644


def archive_dir() -> Path:
    return Path(os.environ.get("MINISOC_ARCHIVE_DIR", "/var/lib/minisoc/archives"))


def chain(prev_hash: str, day: str, file_hash: str, events: int) -> str:
    return hashlib.sha256(f"{prev_hash}|{day}|{file_hash}|{events}".encode()).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _jsonable(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return value if isinstance(value, (int, float, str, bool)) or value is None else str(value)


async def export_day(store, day: date, target: Path) -> int:
    """Écrit les événements du jour (UTC) triés par date ; renvoie leur nombre."""
    start = datetime(day.year, day.month, day.day)
    end = start + timedelta(days=1)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    count, cursor_ts, cursor_id = 0, start - timedelta(microseconds=1), ""
    with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=6) as out:
        while True:  # pagination par (date, identifiant) : pas de décalage coûteux sur les gros volumes
            rows = await store.query(
                "SELECT * EXCEPT (event_id), toString(event_id) AS event_id FROM events "
                "WHERE ts >= {start:DateTime64(3)} AND ts < {end:DateTime64(3)} "
                "AND (ts, toString(event_id)) > ({cts:DateTime64(3)}, {cid:String}) "
                f"ORDER BY ts, event_id LIMIT {BATCH}",
                {"start": start, "end": end, "cts": cursor_ts, "cid": cursor_id},
            )
            for row in rows:
                out.write(json.dumps({k: _jsonable(v) for k, v in row.items()}, ensure_ascii=False) + "\n")
            count += len(rows)
            if len(rows) < BATCH:
                break
            cursor_ts, cursor_id = rows[-1]["ts"], rows[-1]["event_id"]
    tmp.chmod(READABLE)
    target.parent.chmod(READABLE | 0o111)
    tmp.replace(target)
    return count


async def seal_day(session: AsyncSession, store, day: date) -> Archive:
    previous = await session.scalar(select(Archive).order_by(Archive.day.desc()).limit(1))
    if previous and previous.day >= day.isoformat():
        raise ValueError(f"le {day} est déjà scellé ou antérieur à la dernière archive ({previous.day})")
    base = archive_dir()
    relative = Path(f"{day:%Y}") / f"events-{day.isoformat()}.jsonl.gz"
    events = await export_day(store, day, base / relative)
    sha = file_sha256(base / relative)
    prev_hash = previous.chain_hash if previous else GENESIS
    record = Archive(
        day=day.isoformat(),
        path=str(relative),
        events=events,
        size=(base / relative).stat().st_size,
        sha256=sha,
        prev_hash=prev_hash,
        chain_hash=chain(prev_hash, day.isoformat(), sha, events),
    )
    session.add(record)
    await session.commit()
    with (base / "manifest.jsonl").open("a", encoding="utf-8") as manifest:
        manifest.write(
            json.dumps(
                {
                    "day": record.day,
                    "file": record.path,
                    "events": events,
                    "sha256": sha,
                    "prev_hash": prev_hash,
                    "chain_hash": record.chain_hash,
                }
            )
            + "\n"
        )
    log.info("archive scellée : %s (%d événements, %s)", record.day, events, sha[:12])
    return record


async def seal_pending(sessions, store, today: date | None = None) -> list[str]:
    """Scelle les jours manquants jusqu'à la veille, dans l'ordre (la chaîne commence au premier scellement)."""
    today = today or datetime.now(timezone.utc).date()
    yesterday = today - timedelta(days=1)
    async with sessions() as session:
        last = await session.scalar(select(Archive).order_by(Archive.day.desc()).limit(1))
        day = date.fromisoformat(last.day) + timedelta(days=1) if last else yesterday
        sealed = []
        while day <= yesterday and len(sealed) < MAX_CATCH_UP:
            await seal_day(session, store, day)
            sealed.append(day.isoformat())
            day += timedelta(days=1)
    return sealed


def verify_records(records: list[Archive], base: Path) -> list[dict]:
    """Contrôle chaque archive (fichier présent, empreinte, chaînage) ; une rupture se propage aux suivantes."""
    out, prev = [], GENESIS
    for rec in records:
        problems = []
        path = base / rec.path
        if rec.prev_hash != prev:
            problems.append("chaînage rompu (archive précédente modifiée ou supprimée)")
        if chain(rec.prev_hash, rec.day, rec.sha256, rec.events) != rec.chain_hash:
            problems.append("empreinte de chaîne incohérente (registre modifié)")
        if not path.is_file():
            problems.append("fichier absent")
        elif file_sha256(path) != rec.sha256:
            problems.append("fichier modifié depuis le scellement")
        out.append({"day": rec.day, "ok": not problems, "problems": problems})
        prev = rec.chain_hash
    return out


async def verify(session: AsyncSession) -> list[dict]:
    records = list((await session.scalars(select(Archive).order_by(Archive.day))).all())
    return verify_records(records, archive_dir())


async def chain_head(session: AsyncSession) -> Archive | None:
    return await session.scalar(select(Archive).order_by(Archive.day.desc()).limit(1))
