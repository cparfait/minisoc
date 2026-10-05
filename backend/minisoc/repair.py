"""Réparation des alertes HarfangLab dont le contenu brut a été tronqué au stockage (avant l'allègement des alertes
volumineuses) : contenu relu dans la console (jeton en lecture seule), allégé, puis réenregistré sous le même
identifiant d'événement ; l'ancienne ligne tronquée est supprimée. Les archives déjà scellées ne sont pas modifiées.

    docker compose exec api python -m minisoc.cli repair-harfanglab --dry-run
    docker compose exec api python -m minisoc.cli repair-harfanglab
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid

from minisoc.connectors import harfanglab as hl
from minisoc.ecs import COLUMNS
from minisoc.parsers.common import compact_json
from minisoc.parsers.harfanglab import BULKY

log = logging.getLogger(__name__)

REFERENCE_ID = re.compile(r"/security-event/([^/?#]+)")
BATCH = 100


async def truncated(store) -> list[dict]:
    return await store.query(
        "SELECT * EXCEPT (event_id), toString(event_id) AS event_id FROM events "
        "WHERE module = 'harfanglab' AND NOT isValidJSON(raw) ORDER BY ts"
    )


async def repair_harfanglab(store, cfg: dict, dry_run: bool = False) -> dict:
    rows = await truncated(store)
    report = {"truncated": len(rows), "repaired": 0, "not_found": 0, "errors": 0, "dry_run": dry_run}
    if not rows or dry_run:
        return report
    if not hl.configured(cfg):
        raise RuntimeError("HarfangLab n'est pas configuré (Intégrations › HarfangLab)")
    async with hl.make_client(cfg) as client:
        for start in range(0, len(rows), BATCH):
            fixed, ids = [], []
            for row in rows[start : start + BATCH]:
                match = REFERENCE_ID.search(str(row.get("reference") or ""))
                if not match:
                    report["not_found"] += 1
                    continue
                try:
                    response = await client.get(f"/api/data/alert/alert/Alert/{match.group(1)}/")
                    if response.status_code == 404:
                        report["not_found"] += 1
                        continue
                    response.raise_for_status()
                    raw = compact_json(response.json(), drop=BULKY)
                except Exception as exc:  # noqa: BLE001
                    log.warning("alerte %s non relue : %s", match.group(1), exc)
                    report["errors"] += 1
                    continue
                new = {**row, "raw": raw, "event_id": uuid.UUID(row["event_id"])}
                fixed.append([new.get(c, "") for c in COLUMNS])
                ids.append(row["event_id"])
            if not fixed:
                continue
            # Ajout de la version lisible, puis suppression de la seule version tronquée (même identifiant)
            await store.client.insert("events", fixed, column_names=list(COLUMNS))
            await store.client.command(
                "ALTER TABLE events DELETE WHERE event_id IN {ids:Array(UUID)} AND NOT isValidJSON(raw)",
                parameters={"ids": ids},
                settings={"mutations_sync": 1},
            )
            report["repaired"] += len(fixed)
            await asyncio.sleep(0.2)  # ménage la console HarfangLab
    return report
