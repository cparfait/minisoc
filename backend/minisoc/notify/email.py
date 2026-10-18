"""Envoi d'e-mails SMTP avec chiffrement strict.

  starttls : STARTTLS exigé (échec si le serveur ne le propose pas), certificat vérifié — port 587 ou 25
  ssl      : TLS implicite, certificat vérifié — port 465
  none     : clair, réservé à un relais interne sans TLS (déconseillé)
"""

from __future__ import annotations

import re
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import aiosmtplib


class EmailConfigError(ValueError):
    pass


def configured(cfg: dict) -> bool:
    return bool(cfg.get("smtp_host") and cfg.get("smtp_from") and cfg.get("smtp_to"))


def _tls_context(cfg: dict) -> ssl.SSLContext:
    context = ssl.create_default_context(cadata=cfg.get("smtp_ca_cert") or None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def header_safe(value: str, limit: int = 250) -> str:
    """Valeur d'en-tête sur une ligne : un saut de ligne venu d'un log ferait refuser tout le message.

    split() sans argument coupe aussi sur les séparateurs Unicode (U+0085, U+2028, U+2029).
    """
    return " ".join(_CONTROL_CHARS.sub(" ", value).split())[:limit]


async def send_email(cfg: dict, subject: str, text: str, html: str | None = None,
                     to: list[str] | None = None) -> None:
    recipients = to or cfg.get("smtp_to") or []
    if not cfg.get("smtp_host") or not cfg.get("smtp_from") or not recipients:
        raise EmailConfigError("Messagerie non configurée (serveur, expéditeur ou destinataires manquants)")
    message = EmailMessage()
    message["From"] = cfg["smtp_from"]
    message["To"] = ", ".join(recipients)
    message["Subject"] = header_safe(subject)
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain=str(cfg["smtp_from"]).split("@")[-1] or "minisoc")
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")

    security = cfg.get("smtp_security", "starttls")
    await aiosmtplib.send(
        message,
        hostname=cfg["smtp_host"],
        port=int(cfg.get("smtp_port") or (465 if security == "ssl" else 587)),
        username=cfg.get("smtp_user") or None,
        password=cfg.get("smtp_password") or None,
        use_tls=security == "ssl",
        start_tls=security == "starttls",  # True : STARTTLS obligatoire, pas de repli en clair
        tls_context=_tls_context(cfg) if security != "none" else None,
        local_hostname="minisoc",
        timeout=20,
    )
