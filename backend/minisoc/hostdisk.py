"""Espace des disques de la VM : alerte UC-63 quand une partition se remplit.

Le worker tourne dans un conteneur et ne voit pas les disques de l'hôte. Le service minisoc-disk de la VM
(deploy/disk, toutes les 5 minutes) relève les systèmes de fichiers locaux (/, /var/log, disque de données
/var/lib/docker, /boot…) et dépose `disques.json` dans un dossier monté en lecture seule dans le worker.

- une partition dont l'espace **ou** les inodes dépassent le seuil (Paramètres › Détection, 85 % par défaut) donne
  une alerte moyenne, haute à partir de 95 % ; une alerte par point de montage, clôturée automatiquement (avec une
  trace) quand l'occupation redescend de 3 points sous le seuil (pas d'alerte qui clignote autour du seuil) ;
- un relevé présent mais vieux de plus d'une heure (service arrêté, minuterie désactivée) donne aussi une alerte :
  sans relevé, la VM pourrait se remplir sans que personne ne le voie. Aucun relevé du tout (poste de
  développement) : rien n'est signalé.

L'état (dernier relevé, partitions, seuil) est gardé dans Redis pour la page Statistiques.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import redis.asyncio as aioredis
from sqlalchemy import select

from minisoc.alerts import SYSTEM, Detection
from minisoc.detections import entity_parts
from minisoc.models import OPEN_STATUSES, Alert, AlertHistory
from minisoc.rules.engine import entity_key, render_title
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

DISK_RULE = "UC-63"
REPORT_FILE = "disques.json"
STATUS_KEY = "minisoc:host:disks"  # état du dernier relevé (page Statistiques)
SINCE_KEY = "minisoc:host:disks:since"  # point de montage -> début du dépassement
REPORT_ENTITY = "relevé des disques"  # entité de l'alerte « relevé arrêté »
MAX_REPORT_BYTES = 1024 * 1024
STALE_AFTER = timedelta(hours=1)
HIGH_PERCENT = 95  # alerte haute à partir de cette occupation
RESOLVE_MARGIN = 3  # clôture quand l'occupation repasse sous seuil − 3 points
CHECK_SECONDS = 60
DEFAULT_THRESHOLD = 85


class HostDiskError(ValueError):
    pass


def read_report(path: Path) -> dict | None:
    """Relevé déposé par le service de la VM ; None s'il n'y en a pas (installation sans le service)."""
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            raise HostDiskError(f"{path.name} trop volumineux")
        data = json.loads(path.read_bytes())
    except FileNotFoundError:
        return None
    except ValueError as exc:
        raise HostDiskError(f"{path.name} illisible : {exc}") from None
    if not isinstance(data, dict):
        raise HostDiskError(f"{path.name} : objet JSON attendu")
    return data


def _percent(value) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


def _size(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def assess(report: dict | None, now: datetime, threshold: int, error: str = "") -> dict:
    """Relevé → état affiché et évalué : partitions (occupation, dépassement), ancienneté du relevé."""
    status = {"state": "absent", "error": error, "at": None, "age_minutes": None, "host": "",
              "threshold": threshold, "high": HIGH_PERCENT, "filesystems": [], "checked_at": now.isoformat()}
    if error:
        status["state"] = "error"
        return status
    if report is None:
        return status
    try:
        at = _aware(datetime.fromisoformat(str(report.get("at"))))
    except ValueError:
        status.update(state="error", error="relevé sans date valide")
        return status
    filesystems = []
    for fs in report.get("filesystems") or []:
        if not isinstance(fs, dict) or not str(fs.get("mount") or "").startswith("/"):
            continue
        percent, inodes = _percent(fs.get("percent")), _percent(fs.get("inodes_percent"))
        filesystems.append({
            "mount": str(fs["mount"])[:200], "device": str(fs.get("device") or "")[:200],
            "fstype": str(fs.get("fstype") or "")[:20], "size": _size(fs.get("size")), "used": _size(fs.get("used")),
            "avail": _size(fs.get("avail")), "percent": percent, "inodes_percent": inodes,
            "over": max(percent, inodes) >= threshold,
        })
    filesystems.sort(key=lambda f: f["mount"])
    age = now - at
    stale = age > STALE_AFTER
    state = "stale" if stale else "alert" if any(f["over"] for f in filesystems) else "ok"
    status.update(state=state, at=at.isoformat(), age_minutes=max(0, int(age.total_seconds() // 60)),
                  host=str(report.get("host") or "")[:100], filesystems=filesystems)
    return status


def findings(status: dict) -> list[dict]:
    """Alertes à lever : partitions au-delà du seuil (relevé à jour), relevé arrêté."""
    if status["state"] == "stale":
        return [{"mount": REPORT_ENTITY, "metric": status["age_minutes"], "severity": 2, "stale": True,
                 "title": f"Espace des disques de la VM non relevé depuis {status['age_minutes'] // 60} h "
                          "(service minisoc-disk arrêté ?)"}]
    if status["state"] not in ("ok", "alert"):
        return []
    out = []
    for fs in status["filesystems"]:
        if not fs["over"]:
            continue
        metric = max(fs["percent"], fs["inodes_percent"])
        what = "plein" if fs["percent"] >= fs["inodes_percent"] else "sans inodes libres"
        out.append({"mount": fs["mount"], "metric": metric, "severity": 3 if metric >= HIGH_PERCENT else 2,
                    "stale": False, "filesystem": fs, "what": what})
    return out


def resolution(mount: str, status: dict) -> str:
    """Raison de clore l'alerte d'un point de montage, ou chaîne vide si elle reste ouverte."""
    if mount == REPORT_ENTITY:
        return "Relevé de l'espace des disques de nouveau à jour" if status["state"] in ("ok", "alert") else ""
    if status["state"] not in ("ok", "alert"):
        return ""  # relevé vieux ou illisible : on ne sait pas, l'alerte reste ouverte
    fs = next((f for f in status["filesystems"] if f["mount"] == mount), None)
    if fs is None:
        return f"{mount} n'est plus monté"
    occupied = max(fs["percent"], fs["inodes_percent"])
    limit = status["threshold"] - RESOLVE_MARGIN
    if occupied < limit:
        return (f"Occupation de {mount} redescendue à {occupied} % "
                f"(seuil {status['threshold']} %, clôture sous {limit} %)")
    return ""


async def load_status(redis: aioredis.Redis) -> dict | None:
    raw = await redis.get(STATUS_KEY)
    return json.loads(raw) if raw else None


class HostDiskJob:
    """Tâche du worker : lit le relevé de la VM chaque minute, lève et clôt les alertes UC-63."""

    def __init__(self, sessions, redis: aioredis.Redis, directory: str, rules: Callable, raise_alert: Callable,
                 exceptions=None) -> None:
        self.sessions, self.redis, self.directory = sessions, redis, Path(directory)
        self.rules, self.raise_alert, self.exceptions = rules, raise_alert, exceptions

    async def run(self) -> None:
        while True:
            try:
                await self.tick()
            except Exception:  # noqa: BLE001 - la tâche continue au passage suivant
                log.exception("espace des disques : lecture du relevé en échec")
            await asyncio.sleep(CHECK_SECONDS)

    async def tick(self, now: datetime | None = None) -> dict:
        now = now or datetime.now(timezone.utc)
        async with self.sessions() as session:
            cfg = await settings_store.load(session)
        threshold = int(cfg.get("disk_alert_percent") or DEFAULT_THRESHOLD)
        try:
            report, error = await asyncio.to_thread(read_report, self.directory / REPORT_FILE), ""
        except (HostDiskError, OSError) as exc:
            report, error = None, str(exc)[:300]
        status = assess(report, now, threshold, error)
        await self.redis.set(STATUS_KEY, json.dumps(status, ensure_ascii=False))
        rule = self.rules().by_id.get(DISK_RULE)
        if rule is None:
            return status
        since = await self.redis.hgetall(SINCE_KEY)
        since = {(k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                 for k, v in since.items()}
        at = datetime.fromisoformat(status["at"]) if status["at"] else now
        host = status["host"] or "VM Mini-SOC"
        for found in findings(status):
            mount = found["mount"]
            if mount not in since:
                since[mount] = (now if found["stale"] else at).isoformat()
                await self.redis.hset(SINCE_KEY, mount, since[mount])
            values = {"file.path": mount, "value": found["metric"]}
            if self.exceptions is not None and self.exceptions.is_excepted(rule.id, values):
                continue
            title = found["title"] if found["stale"] else (
                render_title(rule.title, values) if found["what"] == "plein"
                else f"Disque de la VM sans inodes libres : {mount} ({found['metric']} % des inodes utilisés)")
            # Pas de host.name : l'alerte ne doit pas peser dans le score de risque d'une machine
            details = {"sample": {"file.path": mount}, "vm": host,
                       "disk": found.get("filesystem") or {"report_age_minutes": found["metric"]},
                       "threshold": threshold}
            await self.raise_alert(Detection(
                rule=rule, entity_key=entity_key(rule.group_by, values), severity=found["severity"], title=title,
                first_seen=datetime.fromisoformat(since[mount]), last_seen=now if found["stale"] else at,
                metric=found["metric"], accumulate=False, details=details,
            ))
        await self.resolve(rule.id, status, since)
        return status

    async def resolve(self, rule_id: str, status: dict, since: dict) -> int:
        """Partition revenue sous le seuil, relevé de nouveau à jour : alerte clôturée, avec une trace."""
        resolved = 0
        async with self.sessions() as session:
            alerts = (await session.scalars(select(Alert).where(
                Alert.rule_id == rule_id, Alert.status.in_(OPEN_STATUSES)).with_for_update())).all()
            open_mounts = set()
            for alert in alerts:
                mount = entity_parts(alert.entity_key).get("file.path", "")
                why = resolution(mount, status)
                if not why:
                    open_mounts.add(mount)
                    continue
                alert.status, alert.notify_pending = "resolved", False
                session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="status", detail="resolved"))
                session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="comment",
                                         detail=f"{why} : clôture automatique."))
                log.info("alerte %s clôturée : %s", alert.id, why)
                resolved += 1
            await session.commit()
        # Début de dépassement oublié dès que la partition est revenue sous la limite de clôture
        for mount in list(since):
            if mount not in open_mounts and resolution(mount, status):
                await self.redis.hdel(SINCE_KEY, mount)
        return resolved
