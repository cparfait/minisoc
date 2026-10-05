"""Canaux de notification. Chaque canal lève une exception en cas d'échec (le routeur réessaie)."""

from __future__ import annotations

import html as html_lib
from dataclasses import dataclass

import httpx

from minisoc.config import Settings
from minisoc.notify.email import configured as email_configured
from minisoc.notify.email import send_email

SEVERITY_FR = {"info": "Info", "low": "Faible", "medium": "Moyenne", "high": "Haute", "critical": "Critique"}
_NTFY_PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_HTML_COLOR = {"critical": "#e5484d", "high": "#f76b15", "medium": "#d4a017", "low": "#3e9bdb", "info": "#8b8d98"}
_TEAMS_COLOR = {"critical": "Attention", "high": "Warning", "medium": "Accent", "low": "Default", "info": "Default"}


@dataclass
class AlertMessage:
    alert_id: int
    severity: str
    title: str
    rule: str
    entity: str
    count: int
    first_seen: str
    last_seen: str
    url: str
    escalated: bool = False  # sévérité relevée depuis la première notification
    unhandled_minutes: int = 0  # relance : alerte toujours non prise en charge

    @property
    def subject(self) -> str:
        if self.unhandled_minutes:
            prefix = f"[NON PRISE EN CHARGE depuis {self.unhandled_minutes} min] "
        else:
            prefix = "[ESCALADE] " if self.escalated else ""
        return f"{prefix}[Mini-SOC][{SEVERITY_FR[self.severity]}] {self.title}"

    def body(self) -> str:
        return (
            f"{self.title}\n\n"
            f"Sévérité : {SEVERITY_FR[self.severity]}\n"
            f"Règle : {self.rule}\n"
            f"Entité : {self.entity}\n"
            f"Occurrences : {self.count}\n"
            f"Première détection : {self.first_seen}\n"
            f"Dernière détection : {self.last_seen}\n\n"
            f"Traiter l'alerte : {self.url}\n"
        )

    def html(self) -> str:
        """Version HTML : toutes les valeurs sont échappées (le contenu des alertes vient des journaux)."""
        e = html_lib.escape
        color = _HTML_COLOR[self.severity]
        rows = "".join(
            f"<tr><td style='color:#666;padding:4px 12px 4px 0'>{e(k)}</td><td style='padding:4px 0'>{e(v)}</td></tr>"
            for k, v in (("Règle", self.rule), ("Entité", self.entity), ("Occurrences", str(self.count)),
                         ("Première détection", self.first_seen), ("Dernière détection", self.last_seen))
        )
        return (
            f"<div style='font-family:Segoe UI,Arial,sans-serif;max-width:640px'>"
            f"<div style='border-left:6px solid {color};padding:8px 16px'>"
            f"<div style='color:{color};font-weight:700'>{e(SEVERITY_FR[self.severity])}</div>"
            f"<h2 style='margin:4px 0 12px'>{e(self.title)}</h2>"
            f"<table style='font-size:14px;border-collapse:collapse'>{rows}</table>"
            f"<p><a href='{e(self.url)}' style='display:inline-block;background:#3e63dd;color:#fff;padding:8px 16px;"
            f"border-radius:6px;text-decoration:none'>Traiter l'alerte</a></p></div></div>"
        )


class Channel:
    """Canal de notification. `cfg` = paramètres effectifs (interface, sinon .env), rechargés avant chaque passage."""

    name = ""

    def __init__(self, s: Settings) -> None:
        self.s = s
        self.cfg: dict = {}

    @property
    def configured(self) -> bool:
        raise NotImplementedError


class EmailChannel(Channel):
    name = "email"

    @property
    def configured(self) -> bool:
        return email_configured(self.cfg)

    async def send(self, msg: AlertMessage, recipients: list[str] | None = None) -> None:
        await send_email(self.cfg, msg.subject, msg.body(), html=msg.html(), to=recipients)


class TeamsChannel(Channel):
    """Webhook d'un flux « Workflows » Teams (carte adaptative)."""

    name = "teams"

    @property
    def configured(self) -> bool:
        return bool(self.cfg.get("teams_webhook_url"))

    async def send(self, msg: AlertMessage) -> None:
        card = {
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.4",
            "body": [
                {
                    "type": "TextBlock",
                    "text": msg.subject,
                    "weight": "Bolder",
                    "wrap": True,
                    "color": _TEAMS_COLOR[msg.severity],
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "Règle", "value": msg.rule},
                        {"title": "Entité", "value": msg.entity},
                        {"title": "Occurrences", "value": str(msg.count)},
                        {"title": "Dernière détection", "value": msg.last_seen},
                    ],
                },
            ],
            "actions": [{"type": "Action.OpenUrl", "title": "Traiter l'alerte", "url": msg.url}],
        }
        payload = {
            "type": "message",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}],
        }
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(self.cfg["teams_webhook_url"], json=payload)
            response.raise_for_status()


class NtfyChannel(Channel):
    """Notification mobile via ntfy (publication JSON, compatible UTF-8)."""

    name = "ntfy"

    @property
    def configured(self) -> bool:
        return bool(self.cfg.get("ntfy_url") and self.cfg.get("ntfy_topic"))

    async def send(self, msg: AlertMessage, topic: str | None = None) -> None:
        token = self.cfg.get("ntfy_token")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        payload = {
            "topic": topic or self.cfg["ntfy_topic"],
            "title": msg.subject[:250],
            "message": f"{msg.entity}\n{msg.count} occurrence(s), dernière à {msg.last_seen}",
            "priority": 5 if msg.unhandled_minutes else _NTFY_PRIORITY[msg.severity],
            "tags": ["rotating_light"] if msg.severity == "critical" else ["warning"],
            "click": msg.url,
        }
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(self.cfg["ntfy_url"].rstrip("/"), json=payload, headers=headers)
            response.raise_for_status()
