"""Inventaire des actifs (machines et comptes) : criticité, propriétaire, service.

Alimenté par NinjaOne et Cyberwatch (machines), l'Active Directory (ordinateurs avec leur OU, comptes à privilèges et de
service) et les alertes (machines sans fiche, « à classer »), complété à la main ou par import CSV. Une fiche
classée par la DSI (`reviewed`) n'est jamais modifiée par une synchronisation.

La criticité entre dans la priorité des alertes ; propriétaire et service s'affichent avec les machines touchées.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import re
import time
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.accounts import KEYS as ACCOUNT_KEYS
from minisoc.accounts import ad_configured
from minisoc.accounts import normalize as normalize_account
from minisoc.connectors.cyberwatch import STATE_KEY as CYBERWATCH_KEY
from minisoc.connectors.ninjaone import POSTURE_KEY
from minisoc.models import CRITICALITIES, OPEN_STATUSES, Alert, Asset

log = logging.getLogger(__name__)

CRITICALITY_LABEL = {"low": "basse", "normal": "normale", "high": "haute", "vital": "vitale"}
CRITICALITY_POINTS = {"low": -10, "normal": 0, "high": 10, "vital": 20}
SERVER_OS = re.compile(r"server", re.I)
SERVER_NAME = re.compile(r"^(srv|svr|serveur|dc|ad|fs|sql|web|app|mail|exch)[-_0-9]", re.I)
CACHE_SECONDS = 60


def host_key(name: str) -> str:
    """« PTB-00100.mairie.local » → « ptb-00100 »."""
    return (name or "").strip().lower().split(".")[0]


def key_for(kind: str, name: str) -> str:
    return host_key(name) if kind == "host" else normalize_account(name)


@dataclass
class AssetInfo:
    criticality: str
    owner: str
    service: str
    display_name: str
    asset_type: str

    def label(self) -> str:
        return " · ".join(x for x in (self.owner, self.service) if x)


class AssetIndex:
    """Index en mémoire des fiches (machines et comptes), rechargé au plus toutes les 60 s."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], AssetInfo] = {}
        self.loaded = 0.0

    async def ensure(self, session: AsyncSession) -> AssetIndex:
        if time.monotonic() - self.loaded > CACHE_SECONDS:
            rows = (await session.scalars(select(Asset))).all()
            self.items = {
                (a.kind, a.name): AssetInfo(a.criticality, a.owner, a.service, a.display_name, a.asset_type)
                for a in rows
            }
            self.loaded = time.monotonic()
        return self

    def host(self, name: str) -> AssetInfo | None:
        return self.items.get(("host", host_key(name)))

    def account(self, name: str) -> AssetInfo | None:
        return self.items.get(("account", normalize_account(name)))

    def invalidate(self) -> None:
        self.loaded = 0.0


INDEX = AssetIndex()


def criticality_reasons(index: AssetIndex, hosts: list[str], user: str) -> list[dict]:
    """Points de priorité liés à l'inventaire : la machine ou le compte le plus critique."""
    candidates = []
    for name in hosts:
        info = index.host(name)
        if info:
            candidates.append((CRITICALITY_POINTS.get(info.criticality, 0), "machine", name, info))
    if user:
        info = index.account(user)
        if info:
            candidates.append((CRITICALITY_POINTS.get(info.criticality, 0), "compte", user, info))
    if not candidates:
        return []
    points, what, name, info = max(candidates, key=lambda c: c[0])
    if points == 0:
        return []
    detail = f" ({info.label()})" if info.label() else ""
    return [{"label": f"{what} {CRITICALITY_LABEL[info.criticality]} : {name}{detail}", "points": points}]


# ---------- Écriture ----------


async def upsert(
    session: AsyncSession, kind: str, name: str, *, source: str, reviewed: bool = False, **values
) -> tuple[Asset, bool]:
    """Crée ou complète une fiche. Une fiche classée (`reviewed`) n'est modifiée que par une saisie manuelle."""
    key = key_for(kind, name)
    if not key:
        raise ValueError("nom vide")
    asset = await session.scalar(select(Asset).where(Asset.kind == kind, Asset.name == key))
    created = asset is None
    if created:
        asset = Asset(kind=kind, name=key, display_name=name.strip()[:256], source=source)
        session.add(asset)
    elif asset.reviewed and not reviewed:
        return asset, False
    for attr, value in values.items():
        if value is None or (value == "" and not reviewed):
            continue  # une synchronisation n'efface pas une information connue
        if attr == "criticality" and value not in CRITICALITIES:
            raise ValueError(f"criticité inconnue : {value} ({', '.join(CRITICALITIES)})")
        if isinstance(value, bool):
            setattr(asset, attr, value)
        else:
            setattr(asset, attr, str(value)[:256] if attr != "description" else str(value)[:2000])
    if reviewed:
        asset.reviewed = True
    INDEX.invalidate()
    return asset, created


CSV_COLUMNS = ("nom", "type", "criticite", "proprietaire", "service", "description")
_ALIASES = {
    "name": "nom",
    "kind": "type",
    "criticality": "criticite",
    "criticité": "criticite",
    "owner": "proprietaire",
    "propriétaire": "proprietaire",
}
_KIND = {
    "machine": "host",
    "host": "host",
    "poste": "host",
    "serveur": "host",
    "compte": "account",
    "account": "account",
    "utilisateur": "account",
}
_CRIT = {
    "basse": "low",
    "faible": "low",
    "low": "low",
    "normale": "normal",
    "normal": "normal",
    "haute": "high",
    "élevée": "high",
    "high": "high",
    "vitale": "vital",
    "critique": "vital",
    "vital": "vital",
}


def parse_csv(text: str) -> list[dict]:
    """CSV (séparateur ; ou ,) : nom ; type (machine/compte) ; criticité ; propriétaire ; service ; description.
    L'en-tête est facultatif."""
    sample = text[:2000]
    delimiter = ";" if sample.count(";") >= sample.count(",") else ","
    rows = [r for r in csv.reader(io.StringIO(text), delimiter=delimiter) if any(c.strip() for c in r)]
    if not rows:
        return []
    header = [_ALIASES.get(c.strip().lower(), c.strip().lower()) for c in rows[0]]
    if "nom" in header:
        rows = rows[1:]
    else:
        header = list(CSV_COLUMNS)
    out = []
    for n, row in enumerate(rows, start=1):
        data = {header[i]: c.strip() for i, c in enumerate(row) if i < len(header)}
        if not data.get("nom"):
            continue
        kind = _KIND.get((data.get("type") or "machine").lower())
        crit = _CRIT.get((data.get("criticite") or "normale").lower())
        if not kind:
            raise ValueError(f"ligne {n} : type inconnu « {data.get('type')} » (machine ou compte)")
        if not crit:
            raise ValueError(
                f"ligne {n} : criticité inconnue « {data.get('criticite')} » (basse, normale, haute, vitale)"
            )
        out.append(
            {
                "kind": kind,
                "name": data["nom"],
                "criticality": crit,
                "owner": data.get("proprietaire", ""),
                "service": data.get("service", ""),
                "description": data.get("description", ""),
            }
        )
    return out


# ---------- Synchronisations ----------


async def sync(session: AsyncSession, redis, cfg: dict) -> dict:
    """NinjaOne, Cyberwatch, AD (ordinateurs, comptes sensibles), machines citées par les alertes ouvertes."""
    report = {
        "ninjaone": 0,
        "cyberwatch": 0,
        "ad_computers": 0,
        "ad_accounts": 0,
        "alerts": 0,
        "created": 0,
        "errors": [],
    }

    async def add(kind, name, source, **values):
        _, created = await upsert(session, kind, name, source=source, **values)
        report["created"] += int(created)

    for raw in (await redis.hgetall(POSTURE_KEY)).values():
        device = json.loads(raw)
        if device.get("name"):
            server = str(device.get("class") or "").endswith(("SERVER", "VM_HOST", "VMM_HOST"))
            await add(
                "host",
                device["name"],
                "ninjaone",
                asset_type="serveur" if server else "poste",
                criticality="high" if server else None,
            )
            report["ninjaone"] += 1
    for raw in (await redis.hgetall(CYBERWATCH_KEY)).values():
        try:
            state = json.loads(raw)
        except ValueError:
            continue
        if state.get("name") and state.get("category") not in ("docker_image", "network_target_or_website"):
            await add(
                "host",
                state["name"],
                "cyberwatch",
                asset_type="serveur" if state.get("server") else "poste",
                criticality="high" if state.get("server") else None,
            )
            report["cyberwatch"] += 1
    if ad_configured(cfg):
        from minisoc.ldap_auth import computers

        try:
            for computer in await asyncio.to_thread(computers, cfg):
                server = bool(SERVER_OS.search(computer["os"]))
                await add(
                    "host",
                    computer["name"],
                    "ad",
                    asset_type="serveur" if server else "poste",
                    service=computer["service"],
                    description=computer["description"],
                    owner=computer["owner"],
                    criticality="high" if server else None,
                )
                report["ad_computers"] += 1
        except Exception as exc:  # noqa: BLE001 - l'inventaire continue sans l'annuaire
            report["errors"].append(f"annuaire : {str(exc)[:200]}")
    for role, key in ACCOUNT_KEYS.items():
        for raw in (await redis.hgetall(key)).values():
            account = json.loads(raw)
            await add(
                "account",
                account.get("name", ""),
                "ad",
                asset_type="administrateur" if role == "admin" else "service",
                owner=account.get("display_name") or "",
                description=account.get("description") or "",
                criticality="high" if role == "admin" else None,
            )
            report["ad_accounts"] += 1
    from minisoc.detections import alert_detections

    seen = set()
    for alert in (await session.scalars(select(Alert).where(Alert.status.in_(OPEN_STATUSES)))).all():
        for _, _, host, _ in alert_detections(alert):
            if host and host_key(host) not in seen:
                seen.add(host_key(host))
                server = bool(SERVER_NAME.match(host))
                await add(
                    "host",
                    host,
                    "alertes",
                    asset_type="serveur" if server else "",
                    criticality="high" if server else None,
                )
    report["alerts"] = len(seen)
    await session.commit()
    INDEX.invalidate()
    return report
