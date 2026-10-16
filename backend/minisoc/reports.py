"""Rapport mensuel (F-29) : activité de sécurité du mois, pour la direction et le suivi dans le temps.

Indicateurs : volume d'événements par source, alertes (sévérité, règles, sources, qualification, faux positifs),
délais de prise en charge et de clôture, incidents, blocages d'IP, attaques d'authentification (IP, pays),
comparaison avec le mois précédent. Envoyé le 1er du mois (même heure et destinataires que le résumé quotidien),
consultable et téléchargeable dans la page Rapports.
"""

from __future__ import annotations

import html
import statistics
from collections import Counter
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.ecs import SEVERITY_NAMES, severity_name
from minisoc.models import OPEN_STATUSES, Alert, AlertHistory, Block, Incident

MONTHS = ("janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre",
          "novembre", "décembre")
SEVERITY_FR = {"critical": "critique", "high": "haute", "medium": "moyenne", "low": "faible", "info": "info"}
VERDICT_FR = {"attack": "attaque", "suspicious": "suspect", "benign": "erreur d'utilisateur"}
MODULE_FR = {"sophos_xgs": "Sophos XGS", "bitdefender": "Bitdefender", "harfanglab": "HarfangLab",
             "windows": "Windows / AD", "m365": "Microsoft 365", "crowdsec": "CrowdSec", "vectra": "Vectra",
             "varonis": "Varonis", "ogo": "OGO Security", "syslog": "Syslog générique", "unparsed": "Non analysé"}
SYSTEM_ACTORS = {"système", "system"}


def month_bounds(month: date, tz: ZoneInfo) -> tuple[datetime, datetime]:
    start = datetime(month.year, month.month, 1, tzinfo=tz)
    nxt = datetime(month.year + (month.month == 12), month.month % 12 + 1, 1, tzinfo=tz)
    return start.astimezone(timezone.utc), nxt.astimezone(timezone.utc)


def previous_month(month: date) -> date:
    return date(month.year - (month.month == 1), (month.month - 2) % 12 + 1, 1)


def month_label(month: date) -> str:
    return f"{MONTHS[month.month - 1]} {month.year}"


def _minutes(values: list[float]) -> dict:
    if not values:
        return {"count": 0, "median": None, "p90": None}
    ordered = sorted(values)
    return {"count": len(values), "median": round(statistics.median(ordered)),
            "p90": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.9))])}


async def monthly_report(db: AsyncSession, store, month: date, tz: ZoneInfo) -> dict:
    start, end = month_bounds(month, tz)
    prev_start, prev_end = month_bounds(previous_month(month), tz)

    alerts = (await db.scalars(select(Alert).where(Alert.created_at >= start, Alert.created_at < end))).all()
    previous_total = await db.scalar(select(func.count()).select_from(Alert)
                                     .where(Alert.created_at >= prev_start, Alert.created_at < prev_end)) or 0
    ids = [a.id for a in alerts]
    history: dict[int, list[AlertHistory]] = {}
    if ids:
        for h in (await db.scalars(select(AlertHistory).where(AlertHistory.alert_id.in_(ids))
                                   .order_by(AlertHistory.ts))).all():
            history.setdefault(h.alert_id, []).append(h)

    by_severity = Counter(severity_name(a.severity) for a in alerts)
    by_status = Counter(a.status for a in alerts)
    by_module = Counter(m for a in alerts for m in (a.modules or []))
    by_rule = Counter((a.rule_id, a.rule_name) for a in alerts)
    verdicts = Counter(((a.details or {}).get("qualification") or {}).get("verdict") for a in alerts)
    acknowledge, resolve = [], []
    for a in alerts:
        human = [h for h in history.get(a.id, []) if h.actor not in SYSTEM_ACTORS
                 and h.action in ("status", "assign", "comment")]
        if human and a.created_at:
            acknowledge.append((human[0].ts - a.created_at).total_seconds() / 60)
        closed = [h for h in history.get(a.id, [])
                  if h.action == "status" and h.detail in ("resolved", "false_positive")]
        if closed and a.created_at:
            resolve.append((closed[-1].ts - a.created_at).total_seconds() / 60)
    closed_count = by_status["resolved"] + by_status["false_positive"]

    incidents_opened = (await db.scalars(select(Incident).where(Incident.created_at >= start,
                                                                Incident.created_at < end))).all()
    incidents_closed = await db.scalar(select(func.count()).select_from(Incident)
                                       .where(Incident.closed_at >= start, Incident.closed_at < end)) or 0
    blocks = await db.scalar(select(func.count()).select_from(Block)
                             .where(Block.created_at >= start, Block.created_at < end)) or 0
    open_now = await db.scalar(select(func.count()).select_from(Alert).where(Alert.status.in_(OPEN_STATUSES))) or 0

    params = {"s": start.replace(tzinfo=None), "e": end.replace(tzinfo=None)}
    window = "ts >= {s:DateTime64(3)} AND ts < {e:DateTime64(3)}"
    try:
        events = await store.query(f"SELECT module, count() AS n FROM events WHERE {window} GROUP BY module "
                                   "ORDER BY n DESC", params)
        auth = (await store.query(
            "SELECT countIf(outcome = 'failure') AS failures, countIf(outcome = 'success') AS successes, "
            "uniqExactIf(source_ip, outcome = 'failure' AND source_ip != '') AS ips, "
            "uniqExactIf(user_name, outcome = 'failure') AS users "
            f"FROM events WHERE {window} AND category = 'authentication'", params))[0]
        countries = await store.query(
            "SELECT source_country AS country, count() AS failures, uniqExact(source_ip) AS ips FROM events "
            f"WHERE {window} AND category = 'authentication' AND outcome = 'failure' AND source_country != '' "
            "GROUP BY country ORDER BY failures DESC LIMIT 10", params)
        attackers = await store.query(
            "SELECT source_ip AS ip, count() AS failures, uniqExact(user_name) AS users, "
            "any(source_country) AS country, any(source_as) AS asn FROM events "
            f"WHERE {window} AND category = 'authentication' AND outcome = 'failure' AND source_ip != '' "
            "GROUP BY ip ORDER BY failures DESC LIMIT 10", params)
        events_error = ""
    except Exception as exc:  # noqa: BLE001 - le rapport reste utile sans la base des événements
        events, auth, countries, attackers = [], {"failures": 0, "successes": 0, "ips": 0, "users": 0}, [], []
        events_error = f"base des événements indisponible ({type(exc).__name__})"

    return {
        "month": month.strftime("%Y-%m"),
        "label": month_label(month),
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "events": {"total": sum(r["n"] for r in events), "by_module": [{"module": r["module"], "count": r["n"]}
                                                                       for r in events], "error": events_error},
        "alerts": {
            "total": len(alerts),
            "previous_total": previous_total,
            "by_severity": {name: by_severity.get(name, 0) for name in reversed(SEVERITY_NAMES)},
            "by_status": dict(by_status),
            "by_module": [{"module": m, "count": n} for m, n in by_module.most_common(10)],
            "top_rules": [{"rule_id": r, "name": n, "count": c} for (r, n), c in by_rule.most_common(10)],
            "verdicts": {VERDICT_FR[k]: v for k, v in verdicts.items() if k in VERDICT_FR},
            "false_positive_rate": round(100 * by_status["false_positive"] / closed_count) if closed_count else None,
            "still_open": sum(by_status[s] for s in OPEN_STATUSES),
            "open_now": open_now,
            "time_to_acknowledge_min": _minutes(acknowledge),
            "time_to_close_min": _minutes(resolve),
        },
        "incidents": {
            "opened": len(incidents_opened),
            "closed": incidents_closed,
            "items": [{"id": i.id, "title": i.title, "status": i.status, "severity": severity_name(i.severity),
                       "category": i.category, "personal_data": i.personal_data} for i in incidents_opened],
        },
        "blocks": blocks,
        "auth": {**auth, "countries": countries, "top_attackers": attackers},
    }


def _duration(minutes: int | None) -> str:
    if minutes is None:
        return "—"
    if minutes < 60:
        return f"{minutes} min"
    if minutes < 48 * 60:
        return f"{minutes / 60:.1f} h".replace(".", ",")
    return f"{minutes / 1440:.1f} j".replace(".", ",")


def _trend(current: int, previous: int) -> str:
    if not previous:
        return "pas de comparaison (mois précédent sans alerte)" if current else "aucune alerte"
    delta = round(100 * (current - previous) / previous)
    return f"{'+' if delta >= 0 else ''}{delta} % par rapport au mois précédent ({previous})"


def render_markdown(r: dict) -> str:
    a, inc, auth = r["alerts"], r["incidents"], r["auth"]
    lines = [
        f"# Rapport de sécurité : {r['label']}",
        "",
        "## Synthèse",
        "",
        f"- **{a['total']} alertes** ({_trend(a['total'], a['previous_total'])}) : "
        + ", ".join(f"{SEVERITY_FR[k]} {v}" for k, v in a["by_severity"].items() if v) + ".",
        f"- **{inc['opened']} incident(s)** ouvert(s), {inc['closed']} clos ; **{r['blocks']}** blocage(s) d'IP.",
        f"- Délai de prise en charge (médiane) : **{_duration(a['time_to_acknowledge_min']['median'])}** ; "
        f"délai de clôture (médiane) : **{_duration(a['time_to_close_min']['median'])}**.",
        f"- Alertes du mois encore ouvertes : **{a['still_open']}** (toutes périodes : {a['open_now']}).",
        f"- Authentification : {auth['failures']} échecs depuis {auth['ips']} adresses, "
        f"visant {auth['users']} comptes.",
    ]
    if a["false_positive_rate"] is not None:
        lines.append(f"- Taux de faux positifs parmi les alertes clôturées : {a['false_positive_rate']} %.")
    lines += ["", "## Alertes par règle", "", "| Règle | Alertes |", "| --- | --- |"]
    lines += [f"| {x['rule_id']} – {x['name']} | {x['count']} |" for x in a["top_rules"]] or ["| — | 0 |"]
    lines += ["", "## Alertes par source", "", "| Source | Alertes |", "| --- | --- |"]
    lines += [f"| {MODULE_FR.get(x['module'], x['module'])} | {x['count']} |" for x in a["by_module"]] or ["| — | 0 |"]
    if a["verdicts"]:
        lines += ["", "Qualification automatique des alertes d'authentification : "
                  + ", ".join(f"{k} {v}" for k, v in a["verdicts"].items()) + "."]
    lines += ["", "## Incidents", ""]
    lines += [f"- n° {i['id']} · {i['title']} ({i['severity']}, {i['status']})"
              + (" — données personnelles concernées" if i["personal_data"] else "")
              for i in inc["items"]] or ["Aucun."]
    lines += ["", "## Attaques d'authentification", "", "| Adresse | Pays | Opérateur | Échecs | Comptes |",
              "| --- | --- | --- | --- | --- |"]
    lines += [f"| {x['ip']} | {x['country'] or '?'} | {x['asn'] or '?'} | {x['failures']} | {x['users']} |"
              for x in auth["top_attackers"]] or ["| — | | | 0 | 0 |"]
    lines += ["", "## Volume collecté", "", "| Source | Événements |", "| --- | --- |"]
    lines += [f"| {MODULE_FR.get(x['module'], x['module'])} | {x['count']:,} |".replace(",", " ")
              for x in r["events"]["by_module"]] or ["| — | 0 |"]
    if r["events"]["error"]:
        lines += ["", f"_Remarque : {r['events']['error']}._"]
    return "\n".join(lines) + "\n"


def render_html(r: dict, public_url: str) -> str:
    e = html.escape
    a, inc, auth = r["alerts"], r["incidents"], r["auth"]
    tiles = [
        (a["total"], "alertes", _trend(a["total"], a["previous_total"])),
        (inc["opened"], "incidents ouverts", f"{inc['closed']} clos"),
        (_duration(a["time_to_acknowledge_min"]["median"]), "prise en charge (médiane)", ""),
        (r["blocks"], "blocages d'IP", ""),
    ]
    tile_html = "".join(
        f"<td style='padding:10px 14px;border:1px solid #ddd;border-radius:6px'><div style='font-size:22px;"
        f"font-weight:700'>{e(str(v))}</div><div>{e(label)}</div>"
        f"<div style='color:#666;font-size:12px'>{e(sub)}</div></td>"
        for v, label, sub in tiles)
    rules = "".join(f"<tr><td>{e(x['rule_id'])} – {e(x['name'])}</td>"
                    f"<td style='text-align:right'>{x['count']}</td></tr>" for x in a["top_rules"])
    severities = ", ".join(f"{SEVERITY_FR[k]} {v}" for k, v in a["by_severity"].items() if v) or "aucune"
    attackers = "".join(f"<tr><td>{e(x['ip'])}</td><td>{e(x['country'] or '?')}</td><td>{x['failures']}</td>"
                        f"<td>{x['users']}</td></tr>" for x in auth["top_attackers"][:5])
    return (
        "<div style='font-family:Segoe UI,Arial,sans-serif;color:#222;max-width:760px'>"
        f"<h2>Rapport de sécurité : {e(r['label'])}</h2>"
        f"<table style='border-collapse:separate;border-spacing:8px'><tr>{tile_html}</tr></table>"
        f"<p><b>Alertes par sévérité :</b> {e(severities)}. Encore ouvertes : {a['still_open']} "
        f"(toutes périodes : {a['open_now']}).</p>"
        f"<h3>Règles les plus actives</h3><table style='font-size:14px;border-collapse:collapse'>{rules}</table>"
        f"<h3>Attaques d'authentification</h3><p>{auth['failures']} échecs depuis {auth['ips']} adresses, "
        f"{auth['users']} comptes visés.</p>"
        "<table style='font-size:14px'><tr><th>Adresse</th><th>Pays</th><th>Échecs</th><th>Comptes</th></tr>"
        f"{attackers}</table>"
        f"<p><a href='{e(public_url.rstrip('/'))}/reports?month={e(r['month'])}' style='display:inline-block;"
        "background:#3e63dd;color:#fff;padding:8px 16px;border-radius:6px;text-decoration:none'>"
        "Voir le rapport complet</a></p></div>"
    )


def last_complete_month(now: datetime, tz: ZoneInfo) -> date:
    local = now.astimezone(tz)
    return previous_month(date(local.year, local.month, 1))

