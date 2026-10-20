"""Processus de traitement : file d'attente → analyse → stockage → détection → alertes → notifications.

Lancement : python -m minisoc.worker
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import redis.asyncio as aioredis
from sqlalchemy import select

from minisoc import bus, identity
from minisoc.accounts import SYNC_SECONDS, SensitiveAccounts, ad_configured, sync_from_ad
from minisoc.alerts import SYSTEM, Detection, ExceptionCache, upsert_alert
from minisoc.config import Settings, get_settings
from minisoc.connectors.crowdsec import CrowdSecConnector, ThreatIntel
from minisoc.connectors.cyberwatch import CyberwatchConnector
from minisoc.connectors.gravityzone import GravityZoneConnector
from minisoc.connectors.harfanglab import HarfangLabConnector
from minisoc.connectors.m365 import M365Connector
from minisoc.connectors.ninjaone import NinjaOneConnector
from minisoc.connectors.ogo import OgoConnector
from minisoc.connectors.varonis import VaronisConnector
from minisoc.connectors.vectra import VectraConnector
from minisoc.connectors.wordpress import WordPressJob
from minisoc.coverage import CoverageJob
from minisoc.db import init_db, sessionmaker
from minisoc.decoys import Decoys
from minisoc.detections import ProfileCache, entity_parts, recalibrate
from minisoc.ecs import Event
from minisoc.events_store import EventStore
from minisoc.export import Exporter, alert_payload
from minisoc.geoip import GeoIP
from minisoc.geoip_update import GeoIPUpdater
from minisoc.housekeeping import purge
from minisoc.identity import IDENTITIES, host_key, user_key
from minisoc.integrations import (
    DROPPED_KEY,
    GEOIP_STATUS_KEY,
    configured_missing,
    disabled_modules,
    monitored_sources,
)
from minisoc.models import OPEN_STATUSES, Alert, AlertHistory
from minisoc.notify import Notifier
from minisoc.notify.digest import send_digest
from minisoc.parsers import parse_message
from minisoc.qualify import AuthQualifier, Qualification
from minisoc.response.blocking import expire_blocks
from minisoc.risk import DECOY_RULE, tactics_from_raw
from minisoc.rules import load_rules
from minisoc.rules.custom import load_all
from minisoc.rules.custom import signature as custom_signature
from minisoc.rules.engine import RuleSet, entity_key, render_title
from minisoc.rules.model import Rule
from minisoc.rules.sql import novelty_query, sequence_query, threshold_query
from minisoc.settings_store import FIELDS as SETTING_FIELDS
from minisoc.settings_store import store as settings_store
from minisoc.siem_jobs import ArchiveJob, AssetJob, IocHunter, RiskJob
from minisoc.source_sync import SourceStatusSync
from minisoc.threat_feeds import KevIndex, refresh_certfr, refresh_kev
from minisoc.trivy import TrivyLocalJob

log = logging.getLogger("minisoc.worker")

BATCH = 500
SCHEDULE_SECONDS = 30
NOTIFY_SECONDS = 10
QUALIFY_CACHE_SECONDS = 300
WATERMARK_MARGIN = 60


class Worker:
    def __init__(self, settings: Settings, redis: aioredis.Redis, store: EventStore) -> None:
        self.s = settings
        self.redis = redis
        self.store = store
        self.sessions = sessionmaker()
        self.rule_vars = rule_variables({})
        self.rules = RuleSet(load_rules(settings.rules_dir, variables=self.rule_vars))
        self.custom_sig: tuple = ()  # règles importées : chargées au premier passage de refresh_exceptions
        self.exceptions = ExceptionCache(self.sessions)
        self.profiles = ProfileCache(self.sessions)
        self.exporter = Exporter(redis)
        self.decoys = Decoys()
        self.notifier = Notifier(settings, self.sessions)
        self.notify_event = asyncio.Event()
        self.qualifier = AuthQualifier(store)
        self.qualifications: dict[tuple[str, str], tuple[float, Qualification | None]] = {}
        self.watermarks: dict[str, float] = {}  # règle planifiée -> début de sa dernière évaluation réussie
        # Nom stable : après un redémarrage (nouveau conteneur), le worker retrouve ses messages non acquittés
        self.consumer = os.environ.get("MINISOC_WORKER_NAME", "worker-1")
        self.started = datetime.now(timezone.utc)
        self.intel = ThreatIntel(redis)
        self.geo = GeoIP(settings.geoip_dir)
        self.kev = KevIndex(redis)
        self.accounts = SensitiveAccounts(redis)
        log.info(
            "%d règles chargées (%d match, %d planifiées, %d absence)",
            len(self.rules.rules),
            len(self.rules.match_rules) + len(self.rules.fallback_rules),
            len(self.rules.scheduled_rules),
            len(self.rules.absence_rules),
        )

    # --- Pipeline ---------------------------------------------------------------------------

    async def pipeline(self) -> None:
        await bus.ensure_group(self.redis)
        backlog = True  # au démarrage, retraiter d'abord les messages lus mais non acquittés
        while True:
            response = await self.redis.xreadgroup(
                bus.GROUP_PIPELINE,
                self.consumer,
                {bus.STREAM_RAW: "0" if backlog else ">"},
                count=BATCH,
                block=None if backlog else 2000,
            )
            messages = response[0][1] if response else []
            if backlog and not messages:
                backlog = False
                continue
            if messages:
                await self.process(messages)

    async def process(self, messages: list[tuple[str, dict]]) -> None:
        async with self.sessions() as session:
            cfg = await settings_store.load(session)  # cache de 30 s
        parsed = [
            parse_message(
                fields.get("kind", ""),
                fields.get("payload", ""),
                bitdefender_url=cfg.get("bitdefender_console_url") or "",
                harfanglab_url=cfg.get("harfanglab_url") or "",
            )
            for _, fields in messages
        ]
        # Intégrations désactivées dans le catalogue : événements ignorés (comptés pour la fiche)
        disabled = disabled_modules(cfg)
        events = [ev for ev in parsed if ev.module not in disabled]
        if len(events) != len(parsed):
            dropped: dict[str, int] = {}
            for ev in parsed:
                if ev.module in disabled:
                    dropped[ev.module] = dropped.get(ev.module, 0) + 1
            for module, n in dropped.items():
                await self.redis.hincrby(DROPPED_KEY, module, n)
        for ev in events:
            if ev.user_name:  # compte sensible : administrateur ou compte de service (règles UC-23 à UC-31)
                ev.user_key = user_key(ev.user_name)  # même compte sous toutes ses formes (minisoc/identity.py)
                ev.user_roles = self.accounts.roles(ev.user_name)
            if ev.host_name:
                ev.host_key = host_key(ev.host_name)
            if ev.kind == "alert":  # détection mentionnant une CVE activement exploitée (catalogue KEV)
                kev = self.kev.match(ev.rule_name, ev.threat_name, ev.message)
                if kev:
                    ev.intel = ",".join(filter(None, [ev.intel, *(f"kev:{c}" for c in kev)]))[:512]
            if not ev.source_ip:
                continue
            if not ev.intel:  # renseignement : IP source bannie par CrowdSec (locale ou communautaire)
                ev.intel = self.intel.lookup(ev.source_ip)
            # Pays et opérateur (bases GeoIP locales)
            if not ev.source_country and self.geo.available and cfg.get("geoip_enabled", False):
                ev.source_country, ev.source_as = self.geo.lookup(ev.source_ip)
        # Stockage avant acquittement : en cas d'échec, les messages restent en attente et seront rejoués
        await self.store.insert(events)
        self.exporter.events(events)  # export vers un SIEM / SOC externe (file bornée, jamais bloquant)
        latest: dict[str, datetime] = {}
        for ev in events:
            latest[ev.module] = max(latest.get(ev.module, ev.ts), ev.ts)
        await bus.mark_seen(self.redis, latest)
        for ev in events:
            for rule in self.rules.match(ev):
                await self.on_match(rule, ev)
            decoy = self.decoys.match(ev)
            if decoy:
                await self.raise_decoy(ev, *decoy)
        await self.redis.xack(bus.STREAM_RAW, bus.GROUP_PIPELINE, *[msg_id for msg_id, _ in messages])

    async def on_match(self, rule: Rule, ev: Event) -> None:
        values = ev.ecs()
        if self.exceptions.is_excepted(rule.id, values):
            return
        severity = ev.severity if rule.severity == "from_event" else rule.severity_level
        details: dict = {"sample": _sample(values)}
        if rule.severity == "from_event" and ev.rule_name:
            # Fiche de la détection (catégorie, sévérité recalibrée par la DSI) : appliquée à chaque occurrence,
            # sinon la sévérité de l'outil « escaladerait » de nouveau une alerte déclassée
            severity, extra = recalibrate(self.profiles.get(ev.module, ev.rule_name), severity)
            details.update(extra)
        if ev.kind == "alert" and ev.module in ("harfanglab", "varonis", "vectra"):
            details["tactics"] = tactics_from_raw(ev.raw)  # chaînes d'attaque et score de risque (étiquettes MITRE)
        await self.raise_alert(
            Detection(
                rule=rule,
                entity_key=entity_key(rule.group_by, values),
                severity=severity,
                title=render_title(rule.title, values),
                first_seen=ev.ts,
                last_seen=ev.ts,
                event_ids=[ev.event_id],
                modules=[ev.module],
                reference=ev.reference,
                details=details,
            )
        )

    async def raise_alert(self, det: Detection) -> tuple:
        async with self.sessions() as session:
            alert, action = await upsert_alert(session, det)
            await session.commit()
        if action in ("created", "escalated"):
            log.warning("alerte %s (%s) : %s", alert.id, action, alert.title)
            self.notify_event.set()
            self.exporter.alert(alert_payload(alert, self.s.public_url))
        return alert, action

    async def raise_decoy(self, ev: Event, kind: str, value: str) -> None:
        """Leurre touché (UC-45) : alerte critique, notifiée immédiatement, jamais regroupée."""
        rule = self.rules.by_id.get(DECOY_RULE)
        if rule is None:
            return
        values = {**ev.ecs(), "threat.intel": f"{kind} leurre : {value}"}
        if self.exceptions.is_excepted(rule.id, values):
            return
        await self.raise_alert(Detection(
            rule=rule, entity_key=entity_key(rule.group_by, values), severity=rule.severity_level,
            title=render_title(rule.title, values), first_seen=ev.ts, last_seen=ev.ts, event_ids=[ev.event_id],
            modules=[ev.module], reference=ev.reference,
            details={"sample": _sample({k: v for k, v in values.items() if k != "message"}),
                     "decoy": {"type": kind, "value": value}},
        ))

    # --- Règles planifiées (seuils, séquences) -----------------------------------------------

    async def scheduled_rules(self) -> None:
        while True:
            started = asyncio.get_running_loop().time()
            for rule in self.rules.scheduled_rules:
                try:
                    await self.evaluate(rule)
                except Exception as exc:  # noqa: BLE001
                    log.error("règle %s en échec : %s", rule.id, exc)
            elapsed = asyncio.get_running_loop().time() - started
            await asyncio.sleep(max(1.0, SCHEDULE_SECONDS - elapsed))

    async def evaluate(self, rule: Rule) -> None:
        builder = {"threshold": threshold_query, "sequence": sequence_query, "novelty": novelty_query}[rule.type]
        # Filigrane : événements reçus depuis la dernière évaluation réussie de la règle (+ 60 s de marge pour une
        # insertion concurrente) ; au démarrage, toute la période scrutée
        started = asyncio.get_running_loop().time()
        last = self.watermarks.get(rule.id)
        sql, params = builder(rule, None if last is None else int(started - last) + WATERMARK_MARGIN)
        rows = await self.store.query(sql, params)
        self.watermarks[rule.id] = started
        for row in rows:
            values: dict[str, object] = {fld: row[f"g{i}"] for i, fld in enumerate(rule.group_by)}
            values["value"] = row["value"]
            if self.exceptions.is_excepted(rule.id, values):
                continue
            entity = entity_key(rule.group_by, values)
            qualification = await self.qualification(rule, entity, values, row)
            await self.raise_alert(
                Detection(
                    rule=rule,
                    entity_key=entity,
                    severity=qualification.severity
                    if qualification and qualification.severity is not None
                    else rule.severity_level,
                    title=render_title(rule.title, values),
                    first_seen=_utc(row["first_seen"]),
                    last_seen=_utc(row["last_seen"]),
                    count=int(row["events"]),
                    metric=int(row["value"]),
                    accumulate=False,
                    event_ids=[str(i) for i in row["event_ids"]],
                    modules=list(row["modules"]),
                    details={
                        **({"qualification": qualification.as_dict()} if qualification else {}),
                        "value": int(row["value"]),
                        "window": str(rule.window),
                        "sample_ips": [ip for ip in row["sample_ips"] if ip],
                        "sample_users": [u for u in row["sample_users"] if u],
                    },
                )
            )

    async def qualification(self, rule: Rule, entity: str, values: dict, row: dict) -> Qualification | None:
        """Qualification mise en cache 5 min par (règle, entité) : les règles sont évaluées toutes les 30 s."""
        if not rule.qualify:
            return None
        key = (rule.id, entity)
        cached = self.qualifications.get(key)
        now = asyncio.get_running_loop().time()
        if cached and now - cached[0] < QUALIFY_CACHE_SECONDS:
            return cached[1]
        try:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            home = tuple(c.strip().upper() for c in cfg.get("home_countries") or ["FR"])
            result = await self.qualifier.qualify(rule, values, row, home)
        except Exception as exc:  # noqa: BLE001 - sans qualification, la règle garde sa sévérité
            log.error("qualification %s / %s en échec : %s", rule.id, entity, exc)
            return None
        self.qualifications[key] = (now, result)
        if len(self.qualifications) > 10_000:
            self.qualifications.clear()
        return result

    # --- Sources silencieuses ------------------------------------------------------------------

    async def absence_rules(self) -> None:
        while True:
            last_seen = await bus.sources_last_seen(self.redis)
            now = datetime.now(timezone.utc)
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            disabled = disabled_modules(cfg)
            for rule in self.rules.absence_rules:
                # Sources de la règle + intégrations actives du catalogue déjà vues au moins une fois
                expected = {**{m: d for m, d in monitored_sources(cfg).items() if m in last_seen}, **rule.sources}
                for module, delay in expected.items():
                    if module in disabled:
                        continue
                    seen = last_seen.get(module)
                    if seen is not None and now - seen <= delay:
                        continue
                    if module in configured_missing(cfg) or (seen is None and now - self.started <= delay):
                        continue  # source jamais vue : on lui laisse le délai après le démarrage
                    silent = int((now - seen).total_seconds() // 60) if seen else int(delay.total_seconds() // 60)
                    values = {"event.module": module, "value": silent}
                    if self.exceptions.is_excepted(rule.id, values):
                        continue
                    await self.raise_alert(
                        Detection(
                            rule=rule,
                            entity_key=entity_key(rule.group_by, values),
                            severity=rule.severity_level,
                            title=render_title(rule.title, values),
                            first_seen=seen or now,
                            last_seen=now,
                            accumulate=False,
                            metric=silent,
                            modules=[module],
                            details={"last_seen": seen.isoformat() if seen else None, "silent_minutes": silent},
                        )
                    )
                await self.resolve_returned_sources(rule, expected, last_seen, now)
            await asyncio.sleep(60)

    async def resolve_returned_sources(self, rule: Rule, expected: dict, last_seen: dict, now: datetime) -> None:
        """Source de nouveau active : son alerte « source silencieuse » est clôturée, avec une trace."""
        async with self.sessions() as session:
            alerts = (await session.scalars(
                select(Alert).where(Alert.rule_id == rule.id, Alert.status.in_(OPEN_STATUSES)).with_for_update()
            )).all()
            for alert in alerts:
                module = entity_parts(alert.entity_key).get("event.module", "")
                seen, delay = last_seen.get(module), expected.get(module)
                if not seen or not delay or now - seen > delay or seen <= alert.last_seen:
                    continue
                alert.status, alert.notify_pending = "resolved", False
                local = seen.astimezone(ZoneInfo(self.s.timezone)).strftime("%d/%m/%Y %H:%M")
                session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="status", detail="resolved"))
                session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="comment",
                                         detail=f"Source de nouveau active ({module}) : activité le {local}. "
                                         "Clôture automatique."))
                log.info("alerte %s clôturée : source %s de nouveau active", alert.id, module)
            await session.commit()

    # --- Tâches de fond -----------------------------------------------------------------------

    async def notifications(self) -> None:
        while True:
            try:
                await asyncio.wait_for(self.notify_event.wait(), timeout=NOTIFY_SECONDS * 6)
            except TimeoutError:
                pass  # passage périodique : heures ouvrées atteintes, nouvelles tentatives
            self.notify_event.clear()
            await self.notifier.process_pending()

    async def escalations(self) -> None:
        while True:
            await self.notifier.process_escalations()
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
                if cfg.get("response_enabled") and cfg.get("xgs_url"):
                    expired = await expire_blocks(session, cfg)
                    if expired:
                        log.info("%d blocage(s) d'IP levé(s) à expiration", expired)
            await asyncio.sleep(60)

    async def daily_digest(self) -> None:
        """Résumé quotidien à l'heure choisie ; un verrou Redis garantit un seul envoi par jour."""
        tz = ZoneInfo(self.s.timezone)
        while True:
            try:
                async with self.sessions() as session:
                    cfg = await settings_store.load(session)
                local = datetime.now(timezone.utc).astimezone(tz)
                if cfg.get("digest_enabled") and local.hour == int(cfg.get("digest_hour") or 8):
                    key = f"minisoc:digest:{local.date().isoformat()}"
                    if await self.redis.set(key, "1", nx=True, ex=3 * 86400):
                        await send_digest(self.sessions, self.redis, self.store, self.rules, self.s)
                        log.info("résumé quotidien envoyé")
            except Exception as exc:  # noqa: BLE001 - l'envoi sera retenté le lendemain
                log.error("résumé quotidien en échec : %s", exc)
            await asyncio.sleep(60)

    async def monthly_report(self) -> None:
        """Rapport du mois écoulé, le 1er à l'heure du résumé quotidien ; un seul envoi par mois (verrou Redis)."""
        from minisoc.notify.email import send_email
        from minisoc.reports import last_complete_month, monthly_report, render_html, render_markdown

        tz = ZoneInfo(self.s.timezone)
        while True:
            try:
                async with self.sessions() as session:
                    cfg = await settings_store.load(session)
                    now = datetime.now(timezone.utc)
                    local = now.astimezone(tz)
                    if (cfg.get("report_monthly_enabled", True) and local.day == 1
                            and local.hour == int(cfg.get("digest_hour") or 8)):
                        month = last_complete_month(now, tz)
                        if await self.redis.set(f"minisoc:report:{month:%Y-%m}", "1", nx=True, ex=40 * 86400):
                            report = await monthly_report(session, self.store, month, tz)
                            await send_email(cfg, f"[Mini-SOC] Rapport de sécurité : {report['label']}",
                                             render_markdown(report), html=render_html(report, self.s.public_url),
                                             to=cfg.get("digest_to") or cfg.get("smtp_to") or [])
                            log.info("rapport mensuel %s envoyé", report["month"])
            except Exception as exc:  # noqa: BLE001
                log.error("rapport mensuel en échec : %s", exc)
            await asyncio.sleep(300)

    async def heartbeat(self) -> None:
        """Signe de vie lu par /api/health/full : un worker arrêté ou bloqué est détecté par la sonde externe."""
        while True:
            await self.redis.set(bus.WORKER_HEARTBEAT_KEY, datetime.now(timezone.utc).isoformat(), ex=600)
            await asyncio.sleep(30)

    async def housekeeping(self) -> None:
        """Chaque nuit (et au démarrage) : durées de conservation et nettoyage technique."""
        applied_retention = None
        while True:
            try:
                async with self.sessions() as session:
                    cfg = await settings_store.load(session)
                    days = int(cfg.get("events_retention_days") or 365)
                    if days != applied_retention:
                        await self.store.set_retention(days)
                        applied_retention = days
                        log.info("conservation des événements : %d jours", days)
                    purged = await purge(session, self.s, cfg)
                if purged:
                    log.info("ménage : %s", ", ".join(f"{n} {k}" for k, n in purged.items()))
            except Exception as exc:  # noqa: BLE001
                log.error("ménage en échec : %s", exc)
            await asyncio.sleep(6 * 3600)

    async def threat_feeds(self) -> None:
        """Veille : KEV une fois par jour, CERT-FR toutes les 2 heures (si activée et Internet joignable)."""
        last_kev = last_certfr = 0.0
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            now = asyncio.get_running_loop().time()
            if cfg.get("threat_feeds_enabled"):
                if not last_kev or now - last_kev > 86400:
                    try:
                        log.info("catalogue KEV : %d vulnérabilités", await refresh_kev(self.redis))
                        await self.kev.refresh()
                        last_kev = now
                    except Exception as exc:  # noqa: BLE001
                        log.error("catalogue KEV indisponible : %s", exc)
                        last_kev = now - 86400 + 3600  # nouvel essai dans 1 h
                if not last_certfr or now - last_certfr > 7200:
                    try:
                        log.info("CERT-FR : %d publications", await refresh_certfr(self.redis))
                        last_certfr = now
                    except Exception as exc:  # noqa: BLE001
                        log.error("flux CERT-FR indisponibles : %s", exc)
                        last_certfr = now - 7200 + 900
            await asyncio.sleep(300)

    async def sensitive_accounts(self) -> None:
        """Comptes à privilèges et comptes de service lus dans l'AD chaque heure (si le compte LDAPS est configuré)."""
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            if cfg.get("accounts_ad_sync", True) and ad_configured(cfg):
                await sync_from_ad(self.redis, cfg)
                await identity.sync_users(self.redis, cfg)  # formes du nom de chaque compte (UPN, messagerie…)
                await self.accounts.refresh(cfg)
            await asyncio.sleep(SYNC_SECONDS)

    async def refresh_exceptions(self) -> None:
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            await self.accounts.refresh(cfg)
            await IDENTITIES.refresh(self.redis)
            self.exporter.update(cfg)
            self.decoys = Decoys.from_cfg(cfg)
            variables = rule_variables(cfg)
            async with self.sessions() as session:
                custom = await custom_signature(session)
                # Réglage cité par une règle modifié (ex. pays habituels) ou règle importée ajoutée / modifiée
                if variables != self.rule_vars or custom != self.custom_sig:
                    self.rule_vars, self.custom_sig = variables, custom
                    self.rules = RuleSet(await load_all(session, self.s.rules_dir, variables=variables))
                    log.info("règles rechargées : %d règles (pays habituels %s, %d domaines DNS de confiance)",
                             len(self.rules.rules), ",".join(variables["home_countries"]),
                             len(variables["dns_trusted_domains"]))
            await self.intel.refresh()
            await self.kev.refresh()
            self.geo.reload()
            await self.redis.set(GEOIP_STATUS_KEY, json.dumps({"files": self.geo.files()}), ex=600)
            await self.exceptions.refresh()
            await self.profiles.refresh()
            await asyncio.sleep(60)


def rule_variables(cfg: dict) -> dict:
    """Réglages utilisables dans les filtres des règles (« $home_countries », « $dns_trusted_domains »)."""
    countries = cfg.get("home_countries") or SETTING_FIELDS["home_countries"].default
    trusted = cfg.get("dns_trusted_domains")
    if trusted is None:
        trusted = SETTING_FIELDS["dns_trusted_domains"].default
    return {
        "home_countries": sorted({str(c).strip().upper() for c in countries if str(c).strip()}),
        "dns_trusted_domains": sorted({str(d).strip().lower().strip(".") for d in trusted if str(d).strip()}),
    }


async def supervise(name: str, factory: Callable[[], Awaitable[None]]) -> None:
    """Relance une tâche qui échoue, avec un délai croissant plafonné."""
    delay = 1
    while True:
        try:
            await factory()
            return  # tâche terminée normalement (ex. connecteur désactivé)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("tâche %s arrêtée, relance dans %ss", name, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    await init_db()
    store = await EventStore.connect()
    await store.ensure_schema()
    redis = bus.connect()
    worker = Worker(settings, redis, store)
    await worker.exceptions.refresh()
    await worker.profiles.refresh()
    harfanglab = HarfangLabConnector(sessionmaker(), redis)
    m365 = M365Connector(sessionmaker(), redis)
    ninjaone = NinjaOneConnector(sessionmaker(), redis)
    cyberwatch = CyberwatchConnector(sessionmaker(), redis)
    varonis = VaronisConnector(sessionmaker(), redis)
    vectra = VectraConnector(sessionmaker(), redis)
    ogo = OgoConnector(sessionmaker(), redis)
    geoip_updater = GeoIPUpdater(sessionmaker(), redis, settings.geoip_dir)
    trivy_local = TrivyLocalJob(sessionmaker(), redis, settings.trivy_dir)
    wordpress_job = WordPressJob(sessionmaker(), redis)
    gravityzone = GravityZoneConnector(sessionmaker(), redis)
    crowdsec = CrowdSecConnector(sessionmaker(), redis)
    status_sync = SourceStatusSync(sessionmaker(), redis, store)
    ioc_hunter = IocHunter(sessionmaker(), redis, store, lambda: worker.rules, worker.exceptions,
                           worker.notify_event.set)
    archive_job = ArchiveJob(sessionmaker(), store)
    asset_job = AssetJob(sessionmaker(), redis)
    risk_job = RiskJob(sessionmaker(), store, lambda: worker.rules, worker.raise_alert)
    coverage_job = CoverageJob(sessionmaker(), redis, store, lambda: worker.rules, worker.exceptions,
                               worker.notify_event.set)
    await asyncio.gather(
        supervise("pipeline", worker.pipeline),
        supervise("règles planifiées", worker.scheduled_rules),
        supervise("sources silencieuses", worker.absence_rules),
        supervise("notifications", worker.notifications),
        supervise("exceptions", worker.refresh_exceptions),
        supervise("comptes sensibles", worker.sensitive_accounts),
        supervise("escalade", worker.escalations),
        supervise("signe de vie", worker.heartbeat),
        supervise("veille", worker.threat_feeds),
        supervise("ménage", worker.housekeeping),
        supervise("résumé quotidien", worker.daily_digest),
        supervise("rapport mensuel", worker.monthly_report),
        supervise("harfanglab", harfanglab.run),
        supervise("crowdsec", crowdsec.run),
        supervise("microsoft 365", m365.run),
        supervise("ninjaone", ninjaone.run),
        supervise("cyberwatch", cyberwatch.run),
        supervise("varonis", varonis.run),
        supervise("vectra", vectra.run),
        supervise("ogo", ogo.run),
        supervise("bases GeoIP", geoip_updater.run),
        supervise("trivy (VM)", trivy_local.run),
        supervise("wordpress", wordpress_job.run),
        supervise("gravityzone", gravityzone.run),
        supervise("synchro des statuts", status_sync.run),
        supervise("chasse aux IOC", ioc_hunter.run),
        supervise("archives scellées", archive_job.run),
        supervise("inventaire", asset_job.run),
        supervise("risque et chaînes", risk_job.run),
        supervise("couverture antivirus et EDR", coverage_job.run),
        supervise("export SIEM", worker.exporter.run),
    )


def _sample(values: dict[str, object]) -> dict[str, object]:
    """Champs renseignés de l'événement déclencheur, sérialisables en JSON."""
    out = {}
    for key, value in values.items():
        if value in ("", 0, None):
            continue
        out[key] = value.isoformat() if isinstance(value, datetime) else value
    return out


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


if __name__ == "__main__":
    asyncio.run(main())
