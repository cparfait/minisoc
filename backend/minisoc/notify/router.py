"""Routage des notifications (sévérité, plage horaire) et relance des alertes non prises en charge (F-18)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from minisoc.config import Settings
from minisoc.ecs import SEVERITY_BY_NAME, severity_name
from minisoc.models import OPEN_STATUSES, Alert, AlertHistory
from minisoc.notify.channels import AlertMessage, EmailChannel, NtfyChannel, TeamsChannel
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)
SYSTEM = "système"


class Notifier:
    def __init__(self, settings: Settings, sessions: async_sessionmaker) -> None:
        self.s = settings
        self.sessions = sessions
        self.tz = ZoneInfo(settings.timezone)
        self.channels = {c.name: c for c in (EmailChannel(settings), TeamsChannel(settings), NtfyChannel(settings))}

    def in_business_hours(self, cfg: dict, now: datetime | None = None) -> bool:
        """Heures ouvrées réglées dans Paramètres › Notifications (par défaut lundi-vendredi, 8 h - 18 h)."""
        local = (now or datetime.now(timezone.utc)).astimezone(self.tz)
        days = {int(d) for d in cfg.get("business_days") or ["1", "2", "3", "4", "5"] if str(d).isdigit()}
        start, end = int(cfg.get("business_hours_start", 8)), int(cfg.get("business_hours_end", 18))
        return local.isoweekday() in days and start <= local.hour < end

    def channels_for(self, severity: str, cfg: dict) -> list[str]:
        """Canaux de la sévérité (Paramètres › Notifications) ; à défaut, ceux du fichier .env."""
        route = cfg.get(f"route_{severity}")
        if route is None:
            route = self.s.notify_routes.get(severity, [])
        return [c for c in route if c in self.channels]

    async def _load(self, session: AsyncSession) -> dict:
        cfg = await settings_store.load(session)
        for channel in self.channels.values():
            channel.cfg = cfg
        return cfg

    def _message(self, alert: Alert, unhandled_minutes: int = 0) -> AlertMessage:
        return AlertMessage(
            alert_id=alert.id,
            severity=severity_name(alert.severity),
            title=alert.title,
            rule=f"{alert.rule_id} – {alert.rule_name}",
            entity=alert.entity_key,
            count=alert.count,
            first_seen=_local(alert.first_seen, self.tz),
            last_seen=_local(alert.last_seen, self.tz),
            url=f"{self.s.public_url.rstrip('/')}/alerts/{alert.id}",
            escalated=alert.notified_at is not None and not unhandled_minutes,
            unhandled_minutes=unhandled_minutes,
        )

    # --- Notifications initiales -------------------------------------------------------------------

    async def process_pending(self) -> int:
        """Envoie les notifications en attente. Retourne le nombre d'alertes notifiées."""
        async with self.sessions() as session:
            cfg = await self._load(session)
            alerts = (
                await session.scalars(
                    select(Alert)
                    .where(Alert.notify_pending.is_(True), Alert.status.in_(OPEN_STATUSES))
                    .order_by(Alert.severity.desc(), Alert.id)
                    .limit(50)
                )
            ).all()
            sent = 0
            for alert in alerts:
                severity = severity_name(alert.severity)
                quiet = cfg.get("business_hours_only")
                quiet = self.s.business_hours_only if quiet is None else quiet
                if severity in quiet and not self.in_business_hours(cfg):
                    continue  # attendra l'ouverture des bureaux
                delivered = await self._deliver(self._message(alert), self.channels_for(severity, cfg))
                if delivered is None:
                    continue  # échec : nouvelle tentative au prochain passage
                alert.notify_pending = False
                alert.notified_at = datetime.now(timezone.utc)
                detail = ", ".join(delivered) if delivered else "aucun canal configuré pour cette sévérité"
                session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="notified", detail=detail))
                sent += 1
            await session.commit()
            return sent

    async def _deliver(self, msg: AlertMessage, names: list[str], recipients: list[str] | None = None,
                       ntfy_topic: str | None = None) -> list[str] | None:
        """Retourne les canaux utilisés, [] si aucun n'est configuré, None si tous ont échoué."""
        targets = [self.channels[n] for n in names if self.channels[n].configured]
        if not targets:
            if names:
                log.warning("alerte %s : aucun canal configuré parmi %s", msg.alert_id, names)
            return []
        delivered = []
        for channel in targets:
            try:
                if isinstance(channel, EmailChannel):
                    await channel.send(msg, recipients)
                elif isinstance(channel, NtfyChannel):
                    await channel.send(msg, ntfy_topic)
                else:
                    await channel.send(msg)
                delivered.append(channel.name)
            except Exception as exc:  # noqa: BLE001
                log.error("notification %s de l'alerte %s en échec : %s", channel.name, msg.alert_id, exc)
        return delivered if delivered else None

    # --- Escalade : alerte grave toujours « Nouvelle » après le délai -------------------------------

    async def process_escalations(self) -> int:
        """Relance une seule fois le second contact pour chaque alerte grave restée sans prise en charge."""
        async with self.sessions() as session:
            cfg = await self._load(session)
            if not cfg.get("escalation_enabled"):
                return 0
            minutes = int(cfg.get("escalation_minutes") or 30)
            min_level = SEVERITY_BY_NAME.get(cfg.get("escalation_min_severity") or "critical", 4)
            limit = datetime.now(timezone.utc) - timedelta(minutes=minutes)
            alerts = (
                await session.scalars(
                    select(Alert).where(
                        Alert.status == "new",
                        Alert.severity >= min_level,
                        Alert.reminded_at.is_(None),
                        Alert.notified_at.is_not(None),
                        Alert.notified_at <= limit,
                    ).limit(20)
                )
            ).all()
            recipients = cfg.get("escalation_to") or None
            topic = cfg.get("escalation_ntfy_topic") or None
            names = ["ntfy", "teams", "email"]
            if not any(self.channels[n].configured for n in names):
                return 0  # aucun canal : la relance attendra qu'un canal soit configuré (rien n'est perdu)
            done = 0
            for alert in alerts:
                waited = int((datetime.now(timezone.utc) - alert.notified_at).total_seconds() // 60)
                # Le second contact par e-mail et sur mobile ; Teams pour que toute l'équipe voie la relance
                delivered = await self._deliver(self._message(alert, waited), names, recipients, topic)
                if not delivered:
                    continue  # échec d'envoi : nouvelle tentative au prochain passage
                alert.reminded_at = datetime.now(timezone.utc)
                detail = (f"relance après {waited} min sans prise en charge : "
                          f"{', '.join(delivered) or 'aucun canal configuré'}")
                session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="reminder", detail=detail))
                log.warning("alerte %s relancée (%s)", alert.id, detail)
                done += 1
            await session.commit()
            return done


def _local(value: datetime, tz: ZoneInfo) -> str:
    return value.astimezone(tz).strftime("%d/%m/%Y %H:%M:%S")
