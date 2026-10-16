"""Construction du contexte envoyé à l'IA : texte compact, borné, pseudonymisé, délimité comme non fiable."""

from __future__ import annotations

import re
from datetime import datetime
from zoneinfo import ZoneInfo

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.ai.pseudonymize import Pseudonymizer
from minisoc.ecs import severity_name
from minisoc.events_store import EventStore
from minisoc.models import OPEN_STATUSES, Alert
from minisoc.rules.engine import RuleSet

MAX_EVENTS = 20
MAX_MESSAGE = 200
TZ = ZoneInfo("Europe/Paris")


def _clean(value: object, limit: int = 300) -> str:
    """Neutralise les balises (un journal ne doit pas pouvoir fermer la zone de données) et borne la taille."""
    text = str(value if value is not None else "").replace("<", "‹").replace(">", "›").replace("\n", " ")
    return text[:limit]


def _date(value: datetime | str | None) -> str:
    if not value:
        return "?"
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.astimezone(TZ).strftime("%d/%m/%Y %H:%M:%S")


def wrap(sections: list[str]) -> str:
    return "<donnees_non_fiables>\n" + "\n\n".join(s for s in sections if s) + "\n</donnees_non_fiables>"


async def alert_context(alert: Alert, rules: RuleSet, store: EventStore, db: AsyncSession,
                        pseudo: Pseudonymizer, playbook: str, cyber: dict[str, dict] | None = None) -> str:
    p = pseudo
    rule = rules.by_id.get(alert.rule_id)
    details = alert.details or {}

    entity = alert.entity_key
    for part in entity.split(" | "):
        field, _, value = part.partition("=")
        if field == "user.name":
            entity = entity.replace(part, f"user.name={p.user(value)}")
        elif field == "host.name":
            entity = entity.replace(part, f"host.name={p.host(value)}")
        elif field.endswith(".ip"):
            entity = entity.replace(part, f"{field}={p.ip(value)}")

    lines = [
        "# Alerte",
        f"Titre : {_clean(p.text(alert.title))}",
        f"Règle : {alert.rule_id} – {_clean(alert.rule_name)}",
        f"Description de la règle : {_clean(rule.description if rule else '', 600)}",
        f"Techniques MITRE ATT&CK : {', '.join(rule.mitre) if rule and rule.mitre else 'non renseignées'}",
        f"Sévérité : {severity_name(alert.severity)} · statut : {alert.status}",
        f"Entité : {_clean(entity)}",
        f"Occurrences : {alert.count} · valeur mesurée : {alert.metric}",
        f"Première détection : {_date(alert.first_seen)} · dernière : {_date(alert.last_seen)}",
        f"Sources : {', '.join(alert.modules) or 'inconnues'}",
    ]
    qualification = details.get("qualification")
    if qualification:
        lines.append(f"Qualification automatique : {qualification.get('label')}")
        lines += [f"  - {_clean(p.text(r), 400)}" for r in qualification.get("reasons", [])]
    if details.get("sample_users"):
        lines.append("Comptes observés : " + ", ".join(p.user(u) for u in details["sample_users"][:20]))
    if details.get("sample_ips"):
        lines.append("IP observées : " + ", ".join(p.ip(i) for i in details["sample_ips"][:20]))
    if details.get("entities"):
        grouped = sorted(details["entities"].items(), key=lambda kv: -kv[1])[:30]
        lines.append(f"Entités regroupées ({len(details['entities'])}) : "
                     + ", ".join(f"{_clean(p.text(k), 80)} ({v})" for k, v in grouped))

    events = await store.by_ids(alert.event_ids, limit=MAX_EVENTS)
    ev_lines = [f"# Événements liés ({len(events)} sur {len(alert.event_ids)} conservés)",
                "date | source | catégorie | résultat | motif | service | IP source | compte | poste | fichier | "
                "message"]
    for e in events:
        ev_lines.append(" | ".join([
            _date(e.get("ts")), e.get("module", ""), e.get("category", ""), e.get("outcome", "") or "-",
            e.get("reason", "") or "-", e.get("network_service", "") or "-", p.ip(e.get("source_ip", "")) or "-",
            p.user(e.get("user_name", "")) or "-", p.host(e.get("host_name", "")) or "-",
            _clean(p.text(e.get("file_path", "")), 200) or "-",
            _clean(p.text(e.get("message", "")), MAX_MESSAGE),
        ]))

    history = await _entity_history(alert, store, p)
    related = await _related_alerts(alert, db, p)
    sections = ["\n".join(lines), "\n".join(ev_lines), history, related]
    if cyber:
        sections.append(_patches_section(cyber, p))
    if playbook:
        sections.append("# Fiche réflexe interne associée à la règle\n" + playbook[:3000])
    return wrap(sections)


MAX_RAW = 6000


async def event_context(event: dict, store: EventStore, db: AsyncSession, pseudo: Pseudonymizer,
                        cyber: dict[str, dict] | None = None) -> str:
    """Un événement (bouton « Analyser avec l'IA » de la liste) : champs normalisés, journal brut borné, activité
    récente du même poste / compte / IP et alertes ouvertes qui le concernent."""
    p = pseudo
    user, host = event.get("user_name", ""), event.get("host_name", "")
    src, dst, host_ip = event.get("source_ip", ""), event.get("destination_ip", ""), event.get("host_ip", "")
    labels = {"user": p.user(user), "host": p.host(host), "src": p.ip(src), "dst": p.ip(dst), "host_ip": p.ip(host_ip)}
    lines = [
        "# Événement",
        f"Date : {_date(event.get('ts'))} · source : {event.get('module', '')} ({_clean(event.get('observer', ''))})",
        f"Catégorie : {event.get('category', '') or '-'} · action : {_clean(event.get('action', '')) or '-'} · "
        f"résultat : {event.get('outcome', '') or '-'} · motif : {event.get('reason', '') or '-'}",
        f"Sévérité : {severity_name(int(event.get('severity') or 0))}",
        f"Règle de l'outil : {_clean(event.get('rule_name', '')) or '-'} · "
        f"menace : {_clean(event.get('threat_name', '')) or '-'}",
        f"Renseignement : {_clean(event.get('intel', '')) or '-'}",
        f"IP source : {labels['src'] or '-'} ({event.get('source_country', '') or '?'}, "
        f"{_clean(event.get('source_as', '')) or '?'}) · "
        f"IP destination : {labels['dst'] or '-'}",
        f"Compte : {labels['user'] or '-'} · poste : {labels['host'] or '-'} ({labels['host_ip'] or '-'})",
        f"Fichier : {_clean(p.text(event.get('file_path', ''))) or '-'}",
        f"Message : {_clean(p.text(event.get('message', '')), 1000)}",
    ]
    raw = str(event.get("raw") or "")
    raw_section = "# Journal brut de l'outil" + (" (tronqué)" if len(raw) > MAX_RAW else "") + "\n" + _clean(
        p.text(raw), MAX_RAW)

    activity = ""
    conditions = [(c, v) for c, v in (("host_name", host), ("user_name", user), ("source_ip", src)) if v]
    if conditions:
        where = " OR ".join(f"{c} = {{{c}:String}}" for c, _ in conditions)
        rows = await store.query(
            f"SELECT ts, module, category, outcome, rule_name, message FROM events WHERE ({where}) "
            f"AND ts >= now64(3) - INTERVAL 7 DAY ORDER BY ts DESC LIMIT {MAX_EVENTS}",
            dict(conditions),
        )
        if rows:
            activity = "# Activité des 7 derniers jours du même poste, compte ou IP (récente d'abord)\n" + "\n".join(
                f"- {_date(r['ts'])} | {r['module']} | {r['category']} | {r['outcome'] or '-'} | "
                f"{_clean(p.text(r['rule_name'] or r['message']), MAX_MESSAGE)}" for r in rows
            )
    related = ""
    keys = [f"{f}={v}" for f, v in (("host.name", host), ("user.name", user), ("source.ip", src)) if v]
    if keys:
        alerts = (await db.scalars(
            select(Alert).where(Alert.status.in_(OPEN_STATUSES),
                                or_(*[Alert.entity_key.contains(k) for k in keys])).order_by(Alert.id.desc()).limit(10)
        )).all()
        if alerts:
            related = "# Alertes ouvertes concernant ce poste, ce compte ou cette IP\n" + "\n".join(
                f"- n° {a.id} · {a.rule_id} · {severity_name(a.severity)} · {a.status} · {_clean(p.text(a.title))}"
                for a in alerts
            )
    return wrap(["\n".join(lines), raw_section, activity, related, _patches_section(cyber, p) if cyber else ""])


async def _entity_history(alert: Alert, store: EventStore, p: Pseudonymizer) -> str:
    """Historique d'authentification sur 30 jours de l'IP ou du compte concerné."""
    field, _, value = alert.entity_key.partition("=")
    if " | " in value or field not in ("source.ip", "user.name"):
        return ""
    column = "source_ip" if field == "source.ip" else "user_name"
    rows = await store.query(
        f"SELECT countIf(outcome = 'success') AS ok, countIf(outcome = 'failure') AS ko, "
        f"uniqExact(user_name) AS users, uniqExact(source_ip) AS ips, min(ts) AS first, max(ts) AS last "
        f"FROM events WHERE category = 'authentication' AND {column} = {{v:String}} "
        f"AND ts >= now64(3) - INTERVAL 30 DAY",
        {"v": value},
    )
    if not rows or not (rows[0]["ok"] or rows[0]["ko"]):
        return ""
    r = rows[0]
    label = p.ip(value) if column == "source_ip" else p.user(value)
    return (f"# Historique d'authentification sur 30 jours de {label}\n"
            f"Connexions réussies : {r['ok']} · échecs : {r['ko']} · comptes distincts : {r['users']} · "
            f"IP distinctes : {r['ips']} · première activité : {_date(r['first'])} · dernière : {_date(r['last'])}")


async def _related_alerts(alert: Alert, db: AsyncSession, p: Pseudonymizer) -> str:
    rows = (await db.scalars(
        select(Alert).where(Alert.entity_key == alert.entity_key, Alert.id != alert.id).order_by(Alert.id.desc())
        .limit(10)
    )).all()
    if not rows:
        return ""
    return "# Autres alertes sur la même entité\n" + "\n".join(
        f"- n° {a.id} · {a.rule_id} · {severity_name(a.severity)} · {a.status} · {_date(a.last_seen)} · "
        f"{_clean(p.text(a.title))}" for a in rows
    )


async def situation_context(db: AsyncSession, store: EventStore, sources: list[dict], pseudo: Pseudonymizer,
                            focus: str = "") -> str:
    """Vue d'ensemble pour les questions libres : alertes ouvertes, sources, activité d'authentification ; `focus` :
    détail des machines citées dans la question (voir `host_focus`)."""
    p = pseudo
    alerts = (await db.scalars(
        select(Alert).where(Alert.status.in_(OPEN_STATUSES)).order_by(Alert.severity.desc(), Alert.last_seen.desc())
        .limit(40)
    )).all()
    lines = [f"# Alertes ouvertes ({len(alerts)} affichées, les plus graves d'abord)"]
    for a in alerts:
        verdict = ((a.details or {}).get("qualification") or {}).get("label", "")
        lines.append(f"- n° {a.id} · {severity_name(a.severity)} · {a.rule_id} · {a.status} · {a.count} occ. · "
                     f"{_date(a.last_seen)} · {_clean(p.text(a.title))}" + (f" · {verdict}" if verdict else ""))
    src = ["# État des sources"] + [
        f"- {s['module']} : {s['status']} (dernier événement {_date(s['last_seen']) if s['last_seen'] else 'jamais'})"
        for s in sources
    ]
    top = await store.query(
        "SELECT source_ip AS ip, count() AS n, uniqExact(user_name) AS users FROM events "
        "WHERE ts >= now64(3) - INTERVAL 24 HOUR AND category = 'authentication' AND outcome = 'failure' "
        "AND source_ip != '' GROUP BY ip ORDER BY n DESC LIMIT 10"
    )
    auth = ["# IP les plus actives en échec d'authentification (24 h)"] + [
        f"- {p.ip(r['ip'])} : {r['n']} échecs sur {r['users']} compte(s)" for r in top
    ]
    return wrap([focus, "\n".join(lines), "\n".join(src), "\n".join(auth)])


def _patches_section(cyber: dict[str, dict], p: Pseudonymizer) -> str:
    """Correctifs en attente par machine (Cyberwatch) : produit, version installée → version corrigée, CVE corrigées."""
    lines = ["# État de la machine (Cyberwatch, dernier relevé) : vulnérabilités présentes et correctifs à appliquer",
             "Ce ne sont pas des alertes : c'est l'inventaire des failles et des mises à jour manquantes.",
             "machine : produit version installée → version qui corrige (CVE corrigées, dont KEV / prioritaires)"]
    for name, info in cyber.items():
        head = f"- {p.host(name)} ({_clean(info.get('os', ''), 60) or 'système inconnu'}"
        head += ", redémarrage requis)" if info.get("reboot_required") else ")"
        head += f" : {info.get('cve_count', 0)} CVE dont {info.get('prioritized_count', 0)} prioritaires"
        if info.get("kev"):
            head += f", KEV présentes : {', '.join(info['kev'][:8])}"
        lines.append(head)
        if not info.get("known"):
            lines.append("    correctifs : pas encore relevés")
            continue
        for patch in info.get("patches") or []:
            detail = f"{patch['cves']} CVE"
            if patch.get("kev"):
                detail += f", KEV {', '.join(patch['kev'][:5])}"
            if patch.get("prioritized"):
                detail += f", {patch['prioritized']} prioritaires"
            if patch.get("max_score") is not None:
                detail += f", score max {patch['max_score']}"
            version = ("à installer" if patch.get("kb")
                       else f"{patch['from'] or '?'} → {patch['to'] or 'dernière version'}")
            lines.append(f"    {_clean(patch['product'], 80)} {version} ({detail})")
        rest = int(info.get("patches_total") or 0) - len(info.get("patches") or [])
        if rest > 0:
            lines.append(f"    … et {rest} autre(s) correctif(s)")
    return "\n".join(lines)


MAX_FOCUS_HOSTS = 5


def mentioned_hosts(text: str, known: set[str]) -> list[str]:
    """Machines connues citées dans une question (« que faire sur le PTB-00612 ? »), dans l'ordre d'apparition."""
    found = []
    for token in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}(?:\.[A-Za-z0-9-]+)*", text or ""):
        key = token.lower().split(".")[0]
        if key in known and key not in found:
            found.append(key)
    return found[:MAX_FOCUS_HOSTS]


async def host_focus(db: AsyncSession, names: list[str], cyber: dict[str, dict], pseudo: Pseudonymizer) -> str:
    """Détail des machines citées : alertes ouvertes qui les concernent (avec fichier et message) et état Cyberwatch."""
    if not names:
        return ""
    p = pseudo
    lines = []
    for name in names:
        alerts = (await db.scalars(
            select(Alert).where(Alert.status.in_(OPEN_STATUSES), Alert.entity_key.ilike(f"%host.name={name}%"))
            .order_by(Alert.severity.desc(), Alert.last_seen.desc()).limit(10)
        )).all()
        lines.append(f"# Alertes ouvertes sur {p.host(name.upper())} ({len(alerts)})")
        for a in alerts:
            sample = (a.details or {}).get("sample") or {}
            extra = " · ".join(x for x in (
                _clean(p.text(sample.get("file.path") or ""), 200),
                _clean(p.text(sample.get("message") or ""), MAX_MESSAGE),
            ) if x)
            lines.append(f"- n° {a.id} · {severity_name(a.severity)} · {a.status} · {a.count} occ. · "
                         f"{_date(a.last_seen)} · {_clean(p.text(a.title))}" + (f" · {extra}" if extra else ""))
    sections = ["\n".join(lines)]
    if cyber:
        sections.append(_patches_section(cyber, p))
    return "\n\n".join(sections)
