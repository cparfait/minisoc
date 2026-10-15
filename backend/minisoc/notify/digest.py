"""Résumé quotidien par e-mail (F-19) : ce qui s'est passé en 24 h, ce qui reste à traiter, l'état des sources.

Il reprend aussi les alertes de sévérité faible (dont les erreurs d'utilisateurs qualifiées automatiquement),
qui ne déclenchent pas de notification immédiate.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.ecs import SEVERITY_NAMES, severity_name
from minisoc.models import OPEN_STATUSES, Alert
from minisoc.notify.channels import SEVERITY_FR

STATUS_FR = {"new": "nouvelle", "in_progress": "en cours", "resolved": "résolue", "false_positive": "faux positif"}


@dataclass
class Digest:
    subject: str
    text: str
    html: str


async def build_digest(session: AsyncSession, sources: list[dict], attackers: list[dict], public_url: str,
                       tz: ZoneInfo, now: datetime | None = None, veille: dict | None = None) -> Digest:
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(hours=24)
    rows = await session.execute(
        select(Alert.severity, func.count()).where(Alert.created_at >= since).group_by(Alert.severity)
    )
    created = {name: 0 for name in SEVERITY_NAMES}
    for level, count in rows.all():
        created[severity_name(level)] = count
    open_alerts = (await session.scalars(
        select(Alert).where(Alert.status.in_(OPEN_STATUSES), Alert.severity >= 3)
        .order_by(Alert.severity.desc(), Alert.last_seen.desc()).limit(20)
    )).all()
    unhandled = sum(1 for a in open_alerts if a.status == "new")
    low_recent = (await session.scalars(
        select(Alert).where(Alert.created_at >= since, Alert.severity <= 1).order_by(Alert.id.desc()).limit(10)
    )).all()
    silent = [s for s in sources if s["status"] == "silent"]

    day = now.astimezone(tz).strftime("%d/%m/%Y")
    status = ("à traiter" if unhandled else "rien d'urgent") if not silent else "source(s) silencieuse(s)"
    subject = (f"[Mini-SOC] Point du {day} : {created['critical']} critique(s), {created['high']} haute(s) "
               f"en 24 h — {status}")
    url = public_url.rstrip("/")

    text = [f"Point de sécurité du {day} (dernières 24 h)", ""]
    text.append("Alertes créées : " + ", ".join(f"{SEVERITY_FR[n]} {created[n]}" for n in reversed(SEVERITY_NAMES)))
    text += ["", f"Alertes hautes et critiques ouvertes : {len(open_alerts)} (dont {unhandled} non prises en charge)"]
    text += [f"- [{SEVERITY_FR[severity_name(a.severity)]}] {a.title} ({STATUS_FR[a.status]}) {url}/alerts/{a.id}"
             for a in open_alerts]
    if low_recent:
        text += ["", "Alertes faibles (non notifiées), dont erreurs d'utilisateurs probables :"]
        text += [f"- {a.title} {url}/alerts/{a.id}" for a in low_recent]
    text += ["", "Sources : " + (", ".join(f"{s['module']} SILENCIEUSE" for s in silent) or "toutes actives")]
    if attackers:
        text += ["", "IP les plus actives en échec d'authentification :"]
        text += [f"- {a['ip']} : {a['failures']} échecs sur {a['users']} compte(s)" for a in attackers[:5]]
    new_kev, certfr = _recent_veille(veille, now)
    if new_kev or certfr:
        text += ["", "Veille (24 h) :"]
        text += [f"- Vulnérabilité activement exploitée : {k['cve']} {k['vendor']} {k['product']}"
                 + (" (rançongiciels)" if k.get("ransomware") else "") for k in new_kev]
        text += [f"- CERT-FR {c['kind']} : {c['title']} {c['link']}" for c in certfr]
    text += ["", f"Tableau de bord : {url}/"]

    e = html.escape
    colors = {"critical": "#e5484d", "high": "#f76b15", "medium": "#d4a017", "low": "#3e9bdb", "info": "#8b8d98"}
    counters = "".join(
        f"<td style='padding:8px 14px;border-top:4px solid {colors[n]};text-align:center'>"
        f"<div style='font-size:22px;font-weight:700'>{created[n]}</div>"
        f"<div style='color:#666;font-size:12px'>{e(SEVERITY_FR[n])}</div></td>"
        for n in ("critical", "high", "medium", "low")
    )
    alert_rows = "".join(
        f"<tr><td style='padding:4px 8px;color:{colors[severity_name(a.severity)]};font-weight:600'>"
        f"{e(SEVERITY_FR[severity_name(a.severity)])}</td><td style='padding:4px 8px'>"
        f"<a href='{e(url)}/alerts/{a.id}'>{e(a.title)}</a></td>"
        f"<td style='padding:4px 8px;color:#666'>{e(STATUS_FR[a.status])}</td></tr>"
        for a in open_alerts
    ) or "<tr><td style='padding:4px 8px;color:#666'>Aucune</td></tr>"
    low_rows = "".join(f"<li><a href='{e(url)}/alerts/{a.id}'>{e(a.title)}</a></li>" for a in low_recent)
    source_line = (", ".join(f"<b style='color:#e5484d'>{e(s['module'])} silencieuse</b>" for s in silent)
                   or "toutes actives")
    body = (
        f"<div style='font-family:Segoe UI,Arial,sans-serif;max-width:720px'>"
        f"<h2 style='margin:0 0 12px'>Point de sécurité du {e(day)}</h2>"
        f"<table style='border-collapse:collapse;margin-bottom:16px'><tr>{counters}</tr></table>"
        f"<h3>Alertes hautes et critiques ouvertes ({len(open_alerts)}, dont {unhandled} non prises en charge)</h3>"
        f"<table style='border-collapse:collapse;font-size:14px'>{alert_rows}</table>"
        + (f"<h3>Alertes faibles (non notifiées)</h3><ul style='font-size:14px'>{low_rows}</ul>" if low_rows else "")
        + f"<p><b>Sources :</b> {source_line}</p>"
        + _veille_html(new_kev, certfr, url)
        + f"<p><a href='{e(url)}/' style='display:inline-block;background:#3e63dd;color:#fff;padding:8px 16px;"
        f"border-radius:6px;text-decoration:none'>Ouvrir le tableau de bord</a></p></div>"
    )
    return Digest(subject=subject, text="\n".join(text), html=body)


async def send_digest(sessions, redis, store, rules, settings, to: list[str] | None = None) -> str:
    """Construit et envoie le résumé. Retourne la liste des destinataires."""
    from minisoc import stats
    from minisoc.notify.email import send_email
    from minisoc.settings_store import store as settings_store

    async with sessions() as session:
        sources = await stats.sources_status(redis, rules.absence_rules, await settings_store.load(session))
    try:
        attackers = (await stats.auth_activity(store, top=5))["top_attackers"]
    except Exception:  # noqa: BLE001 - le résumé part même si la base des événements est indisponible
        attackers = []
    from minisoc.archives import chain_head

    async with sessions() as session:
        cfg = await settings_store.load(session)
        from minisoc.api.data import threat_feeds_summary
        veille = await threat_feeds_summary(redis, kev_limit=50)
        digest = await build_digest(session, sources, attackers, settings.public_url, ZoneInfo(settings.timezone),
                                    veille=veille)
        head = await chain_head(session)
    if head:  # ancrage hors de la VM : la dernière empreinte de la chaîne des archives part par e-mail
        anchor = (f"Archives scellées : dernière journée {head.day}, {head.events} événements, "
                  f"empreinte de chaîne {head.chain_hash}")
        digest.text += f"\n\n{anchor}\n"
        note = f"<p style='font-size:12px;color:#666'>{html.escape(anchor)}</p>"
        # Avant la fermeture du bloc principal (dernier </div>)
        cut = digest.html.rfind("</div>")
        digest.html = digest.html[:cut] + note + digest.html[cut:] if cut >= 0 else digest.html + note
    recipients = to or cfg.get("digest_to") or cfg.get("smtp_to") or []
    await send_email(cfg, digest.subject, digest.text, html=digest.html, to=recipients)
    return ", ".join(recipients)


def _recent_veille(veille: dict | None, now: datetime) -> tuple[list[dict], list[dict]]:
    if not veille:
        return [], []
    yesterday = (now - timedelta(days=1)).date().isoformat()
    new_kev = [k for k in veille.get("kev", {}).get("recent", []) if k.get("added", "") >= yesterday][:10]
    since = (now - timedelta(hours=24)).isoformat()
    certfr = [c for c in veille.get("certfr", []) if c.get("date", "") >= since][:10]
    return new_kev, certfr


def _veille_html(new_kev: list[dict], certfr: list[dict], url: str) -> str:
    if not new_kev and not certfr:
        return ""
    e = html.escape
    items = "".join(f"<li><b>{e(k['cve'])}</b> {e(k['vendor'])} {e(k['product'])} : {e(k['name'])}</li>"
                    for k in new_kev)
    items += "".join(f"<li>CERT-FR {e(c['kind'])} : <a href='{e(c['link'])}'>{e(c['title'])}</a></li>"
                     for c in certfr)
    return (f"<h3>Veille (24 h)</h3><ul style='font-size:14px'>{items}</ul>"
            f"<p><a href='{e(url)}/veille'>Page Veille</a></p>")
