"""Statistiques de la page « Statistiques » : volumes, qualité des détections, délais de traitement, MITRE et cibles.

Calculs purs sur les objets de la base (alertes créées pendant la période, leur historique, incidents), sans requête :
l'API charge les données, ce module compte. Chaque bloc renvoie sa **méthode** (source, filtres, formule, effectifs),
affichée telle quelle dans l'interface : un chiffre doit pouvoir se vérifier, pas seulement se croire.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from minisoc.detections import CATEGORY_LABEL
from minisoc.ecs import SEVERITY_NAMES, severity_name
from minisoc.frameworks import TACTICS, TECHNIQUES
from minisoc.models import OPEN_STATUSES, Alert, AlertHistory, Incident, IncidentEntry
from minisoc.reports import SYSTEM_ACTORS, _minutes
from minisoc.risk import DERIVED_RULES, alert_tactics, entities_of, ips_of

MAX_DAYS = 366
DAILY_MAX_DAYS = 92  # au-delà, une barre par semaine
CLOSED = ("resolved", "false_positive")
NO_TOOL = "(sans outil)"
TOP_TOOLS = 6  # courbe par outil : les 6 premiers, le reste dans « autres »
NOISY_MIN_CLOSED = 5  # règle « bruyante » : au moins 5 alertes clôturées…
NOISY_FP_RATE = 50  # … dont au moins 50 % de faux positifs
BACKLOG_AGES = (("lt_1d", "moins de 24 h", timedelta(days=1)), ("lt_7d", "1 à 7 jours", timedelta(days=7)),
                ("lt_30d", "7 à 30 jours", timedelta(days=30)), ("ge_30d", "plus de 30 jours", None))
CONTAINED_LABELS = ("Maîtrisé", "Clos")  # libellés des changements d'état d'un incident (api/incidents.py)


def aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def closer_kind(actor: str) -> str:
    """Qui a clôturé : une personne, le Mini-SOC lui-même, ou l'outil d'origine (synchronisation)."""
    if actor.endswith("(synchro)"):
        return "source"
    return "system" if actor in SYSTEM_ACTORS else "human"


def category_of(alert: Alert) -> str:
    return (alert.details or {}).get("category") or "threat"


def tools_of(alert: Alert) -> list[str]:
    return sorted(set(alert.modules or [])) or [NO_TOOL]


def pct(part: int, whole: int) -> int | None:
    return round(100 * part / whole) if whole else None


# ---------- Découpage du temps ----------


def granularity(since: datetime, until: datetime) -> str:
    return "day" if until - since <= timedelta(days=DAILY_MAX_DAYS) else "week"


def bucket_of(ts: datetime, gran: str, tz: ZoneInfo) -> str:
    day = aware(ts).astimezone(tz).date()
    if gran == "week":
        day -= timedelta(days=day.weekday())  # lundi
    return day.isoformat()


def buckets(since: datetime, until: datetime, gran: str, tz: ZoneInfo) -> list[str]:
    first = date.fromisoformat(bucket_of(since, gran, tz))
    last = date.fromisoformat(bucket_of(until - timedelta(microseconds=1), gran, tz))
    step = timedelta(days=7 if gran == "week" else 1)
    out = []
    while first <= last:
        out.append(first.isoformat())
        first += step
    return out


# ---------- Historique des alertes ----------


def closing_entries(alerts: list[Alert], history: list[AlertHistory]) -> dict[int, AlertHistory]:
    """Pour chaque alerte clôturée, le changement d'état qui l'a mise dans son statut actuel (le dernier, si elle a
    été rouverte puis refermée)."""
    status = {a.id: a.status for a in alerts}
    out: dict[int, AlertHistory] = {}
    for h in sorted(history, key=lambda h: aware(h.ts)):
        if h.action == "status" and h.detail in CLOSED and status.get(h.alert_id) == h.detail:
            out[h.alert_id] = h
    return out


# ---------- Volumes ----------


def volumes(alerts: list[Alert], previous_total: int, since: datetime, until: datetime, tz: ZoneInfo) -> dict:
    gran = granularity(since, until)
    keys = buckets(since, until, gran, tz)
    by_bucket = {k: Counter() for k in keys}
    tool_bucket: dict[str, Counter] = defaultdict(Counter)
    by_severity, by_category, by_tool = Counter(), Counter(), defaultdict(Counter)
    rules: dict[str, dict] = {}
    for a in alerts:
        sev = severity_name(a.severity)
        key = bucket_of(a.created_at, gran, tz)
        by_bucket.setdefault(key, Counter())[sev] += 1
        by_severity[sev] += 1
        by_category[category_of(a)] += 1
        for tool in tools_of(a):
            by_tool[tool][sev] += 1
            tool_bucket[tool][key] += 1
        r = rules.setdefault(a.rule_id, {"rule_id": a.rule_id, "rule_name": a.rule_name, "total": 0,
                                         "occurrences": 0, "severity": 0, "tools": set()})
        r["total"] += 1
        r["occurrences"] += a.count or 1
        r["severity"] = max(r["severity"], a.severity)
        r["tools"].update(tools_of(a))
    tools_sorted = sorted(by_tool, key=lambda t: -sum(by_tool[t].values()))
    top, rest = tools_sorted[:TOP_TOOLS], tools_sorted[TOP_TOOLS:]
    series = {t: [tool_bucket[t][k] for k in keys] for t in top}
    if rest:
        series["autres"] = [sum(tool_bucket[t][k] for t in rest) for k in keys]
    total = len(alerts)
    tool_sum = sum(sum(c.values()) for c in by_tool.values())
    return {
        "granularity": gran,
        "total": total,
        "occurrences": sum(a.count or 1 for a in alerts),
        "previous_total": previous_total,
        "delta_pct": pct(total - previous_total, previous_total),
        "by_severity": {name: by_severity.get(name, 0) for name in reversed(SEVERITY_NAMES)},
        "by_category": [{"category": c, "label": CATEGORY_LABEL.get(c, c), "count": n}
                        for c, n in by_category.most_common()],
        "timeline": [{"bucket": k, **{n: by_bucket[k].get(n, 0) for n in SEVERITY_NAMES}} for k in keys],
        "tool_series": {"buckets": keys, "series": series},
        "by_tool": [{"module": t, "total": sum(by_tool[t].values()),
                     **{n: by_tool[t].get(n, 0) for n in SEVERITY_NAMES}} for t in tools_sorted],
        "by_rule": [{**r, "severity": severity_name(r["severity"]), "tools": sorted(r["tools"])}
                    for r in sorted(rules.values(), key=lambda r: (-r["total"], r["rule_id"]))[:25]],
        "method": [
            "Source : table des alertes du Mini-SOC (PostgreSQL), alertes **créées** pendant la période "
            "(date de création, heure de Paris). Les alertes calculées (score de risque UC-43, chaîne d'attaque UC-44, "
            "IP partagée UC-61) sont incluses : ce sont des alertes à traiter.",
            "Une alerte regroupe les répétitions d'une même détection sur une même entité tant qu'elle est ouverte : "
            f"{total} alerte(s) pour {sum(a.count or 1 for a in alerts)} occurrence(s) détectée(s).",
            f"Comparaison : alertes créées pendant la période précédente de même durée ({previous_total}) ; "
            "évolution = (période − précédente) ÷ précédente.",
            f"Courbe : une barre par {'jour' if gran == 'day' else 'semaine (du lundi)'} "
            f"(par semaine au-delà de {DAILY_MAX_DAYS} jours).",
            "Par outil : une alerte qui cite plusieurs outils (ex. corrélation pare-feu + Microsoft 365) compte pour "
            f"chacun ; la somme par outil ({tool_sum}) peut donc dépasser le total ({total}). "
            f"Graphique par outil : les {TOP_TOOLS} premiers, les autres regroupés.",
            "Catégorie : celle de la fiche de la détection (Règles › Détections des outils) ; sans fiche, « menace ».",
        ],
    }


# ---------- Qualité des détections ----------


def _quality_row(items: list[tuple[Alert, str | None]]) -> dict:
    """items : (alerte, type de clôture ou None si ouverte / clôture sans trace)."""
    status = Counter(a.status for a, _ in items)
    closed = status["resolved"] + status["false_positive"]
    kinds = Counter(k for _, k in items if k)
    fp = status["false_positive"]
    return {
        "total": len(items),
        "open": sum(status[s] for s in OPEN_STATUSES),
        "resolved": status["resolved"],
        "false_positive": fp,
        "closed": closed,
        "fp_rate": pct(fp, closed),
        "closed_by": {"human": kinds["human"], "system": kinds["system"], "source": kinds["source"]},
        "noisy": closed >= NOISY_MIN_CLOSED and (pct(fp, closed) or 0) >= NOISY_FP_RATE,
    }


def quality(alerts: list[Alert], closings: dict[int, AlertHistory]) -> dict:
    items = [(a, closer_kind(closings[a.id].actor) if a.id in closings else None) for a in alerts]
    by_rule: dict[str, list] = defaultdict(list)
    by_tool: dict[str, list] = defaultdict(list)
    names: dict[str, str] = {}
    for a, kind in items:
        by_rule[a.rule_id].append((a, kind))
        names[a.rule_id] = a.rule_name
        for tool in tools_of(a):
            by_tool[tool].append((a, kind))
    verdicts = Counter(((a.details or {}).get("qualification") or {}).get("verdict") for a in alerts)
    rules = [{"rule_id": r, "rule_name": names[r], **_quality_row(v)} for r, v in by_rule.items()]
    rules.sort(key=lambda r: (-r["total"], r["rule_id"]))
    tools = [{"module": t, **_quality_row(v)} for t, v in by_tool.items()]
    tools.sort(key=lambda t: -t["total"])
    total = _quality_row(items)
    untraced = sum(1 for a, kind in items if a.status in CLOSED and kind is None)
    return {
        **total,
        "untraced": untraced,
        "verdicts": {k: verdicts[k] for k in ("attack", "suspicious", "benign") if verdicts[k]},
        "by_rule": rules[:40],
        "by_tool": tools,
        "noisy_rules": [r for r in rules if r["noisy"]],
        "method": [
            "Même périmètre que les volumes : alertes créées pendant la période, dans leur statut **actuel**.",
            "Taux de faux positifs = alertes au statut « faux positif » ÷ alertes clôturées (résolues + faux "
            "positifs). Les alertes encore ouvertes n'entrent pas dans le calcul : un taux sur 2 alertes clôturées "
            "est peu significatif, l'effectif est toujours affiché à côté.",
            "Clôturée par : d'après le dernier changement d'état de l'historique de l'alerte — une personne, "
            "le Mini-SOC (« système » : fin d'un regroupement, source revenue, mise à jour…) ou l'outil d'origine "
            f"(synchronisation de la clôture). {untraced} alerte(s) clôturée(s) sans trace dans l'historique "
            "(anciennes alertes).",
            f"Règle « bruyante » : au moins {NOISY_MIN_CLOSED} alertes clôturées dont au moins {NOISY_FP_RATE} % de "
            "faux positifs → candidate à un réglage (seuil, exception, fiche de détection en « hygiène »).",
            "Qualification automatique : verdict calculé pour les alertes d'authentification (attaque, suspect, "
            "erreur d'utilisateur) lorsqu'il existe.",
        ],
    }


# ---------- Délais de traitement ----------


def delays(
    alerts: list[Alert],
    closings: dict[int, AlertHistory],
    open_now: list[tuple[int, datetime]],
    incidents: list[Incident],
    entries: list[IncidentEntry],
    since: datetime,
    until: datetime,
    tz: ZoneInfo,
    now: datetime,
) -> dict:
    gran = granularity(since, until)
    keys = buckets(since, until, gran, tz)
    ack: dict[str, list[float]] = defaultdict(list)
    close: dict[str, dict[str, list[float]]] = {"human": defaultdict(list), "system": defaultdict(list),
                                                "source": defaultdict(list)}
    ack_bucket: dict[str, list[float]] = defaultdict(list)
    close_bucket: dict[str, list[float]] = defaultdict(list)
    never_ack = 0
    for a in alerts:
        sev = severity_name(a.severity)
        created = aware(a.created_at)
        key = bucket_of(created, gran, tz)
        if a.acknowledged_at:
            minutes = max(0.0, (aware(a.acknowledged_at) - created).total_seconds() / 60)
            ack[sev].append(minutes)
            ack_bucket[key].append(minutes)
        elif a.status in OPEN_STATUSES:
            never_ack += 1
        h = closings.get(a.id)
        if h:
            minutes = max(0.0, (aware(h.ts) - created).total_seconds() / 60)
            kind = closer_kind(h.actor)
            close[kind][sev].append(minutes)
            if kind == "human":
                close_bucket[key].append(minutes)

    def by_severity(values: dict[str, list[float]]) -> dict:
        everything = [v for vs in values.values() for v in vs]
        return {"all": _minutes(everything),
                **{name: _minutes(values.get(name, [])) for name in reversed(SEVERITY_NAMES)}}

    backlog = {key: Counter() for key, _, _ in BACKLOG_AGES}
    for severity, created in open_now:
        age = now - aware(created)
        key = next(k for k, _, limit in BACKLOG_AGES if limit is None or age < limit)
        backlog[key][severity_name(severity)] += 1

    # Incidents : ouverts pendant la période ; délais calculés sur ceux clos pendant la période
    status_entries: dict[int, list[IncidentEntry]] = defaultdict(list)
    for e in sorted(entries, key=lambda e: aware(e.ts)):
        if e.kind == "status":
            status_entries[e.incident_id].append(e)
    opened = [i for i in incidents if since <= aware(i.created_at) < until]
    closed = [i for i in incidents if i.closed_at and since <= aware(i.closed_at) < until]
    to_close = [(aware(i.closed_at) - aware(i.created_at)).total_seconds() / 60 for i in closed]
    to_contain = []
    for i in opened:
        first = next((e for e in status_entries[i.id] if e.detail in CONTAINED_LABELS), None)
        if first:
            to_contain.append(max(0.0, (aware(first.ts) - aware(i.created_at)).total_seconds() / 60))
    by_category = Counter(i.category for i in opened)

    human_closed = sum(len(v) for v in close["human"].values())
    return {
        "granularity": gran,
        "acknowledge": by_severity(ack),
        "close_human": by_severity(close["human"]),
        "close_system": _minutes([v for vs in close["system"].values() for v in vs]),
        "close_source": _minutes([v for vs in close["source"].values() for v in vs]),
        "never_acknowledged_open": never_ack,
        "timeline": [{"bucket": k, "acknowledge": _minutes(ack_bucket[k])["median"],
                      "close": _minutes(close_bucket[k])["median"]} for k in keys],
        "backlog": [{"age": key, "label": label, "total": sum(backlog[key].values()),
                     **{n: backlog[key].get(n, 0) for n in SEVERITY_NAMES}} for key, label, _ in BACKLOG_AGES],
        "backlog_total": len(open_now),
        "incidents": {
            "opened": len(opened),
            "closed": len(closed),
            "still_open": sum(1 for i in opened if i.status != "closed"),
            "time_to_contain": _minutes(to_contain),
            "time_to_close": _minutes(to_close),
            "by_category": [{"category": c, "count": n} for c, n in by_category.most_common()],
        },
        "method": [
            "Prise en charge = date de prise en charge de l'alerte − date de création. Une alerte est prise en "
            "charge la première fois qu'une personne change son statut, se l'assigne ou la rattache à un incident "
            "(même champ que les échéances de traitement). Les alertes jamais prises en charge (clôturées "
            "automatiquement, ou encore nouvelles) n'entrent pas dans ce délai : "
            f"{never_ack} alerte(s) de la période sont ouvertes sans prise en charge.",
            "Clôture = date du changement d'état qui a clôturé l'alerte (historique) − date de création. Le délai "
            f"principal ne compte que les clôtures **faites par une personne** ({human_closed}) ; les clôtures "
            "automatiques (Mini-SOC, outil d'origine) sont affichées à part car elles ne mesurent pas l'équipe.",
            "Médiane : la moitié des alertes a été traitée plus vite. P90 : 90 % des alertes ont été traitées plus "
            "vite (les 10 % restants sont les plus longs). Effectif (n) affiché à côté de chaque délai.",
            "Courbe : médianes des alertes créées dans chaque intervalle ; un intervalle sans alerte traitée est vide.",
            "Stock : alertes ouvertes **aujourd'hui** (nouvelles, en cours, en attente), toutes périodes confondues, "
            "par ancienneté depuis leur création.",
            "Incidents : ouverts pendant la période ; « maîtrisé » = premier passage à l'état Maîtrisé ou Clos "
            "(chronologie de l'incident) ; délai de clôture calculé sur les incidents clos pendant la période.",
        ],
    }


# ---------- MITRE et cibles ----------


def mitre_targets(alerts: list[Alert], rule_mitre: dict[str, list[str]], top: int = 15) -> dict:
    from minisoc.assets import key_for

    kept = [a for a in alerts if a.status != "false_positive" and a.rule_id not in DERIVED_RULES]
    tactic_alerts, tactic_exclusive = Counter(), Counter()
    tactic_detections: dict[str, set[str]] = defaultdict(set)
    tactic_entities: dict[str, set[tuple[str, str]]] = defaultdict(set)
    technique_alerts: Counter = Counter()
    technique_rules: dict[str, set[str]] = defaultdict(set)
    unmapped = 0
    entities: dict[tuple[str, str], dict] = {}
    ips: dict[str, dict] = {}
    for a in kept:
        tactics = alert_tactics(a, rule_mitre)
        targets = entities_of(a)
        if not tactics:
            unmapped += 1
        for t in tactics:
            tactic_alerts[t] += 1
            tactic_detections[t].add(a.rule_id)
            tactic_entities[t].update((kind, key_for("host" if kind == "host" else "account", name))
                                      for kind, name in targets)
        if len(tactics) == 1:
            tactic_exclusive[next(iter(tactics))] += 1
        for technique in rule_mitre.get(a.rule_id, []):
            technique_alerts[technique] += 1
            technique_rules[technique].add(a.rule_id)
        for kind, name in targets:
            key = (kind, key_for("host" if kind == "host" else "account", name))
            e = entities.setdefault(key, {"kind": kind, "name": name, "alerts": 0, "severity": 0, "tools": set(),
                                          "tactics": set(), "rules": set(), "last": aware(a.created_at)})
            e["alerts"] += 1
            e["severity"] = max(e["severity"], a.severity)
            e["tools"].update(tools_of(a))
            e["tactics"].update(tactics)
            e["rules"].add(a.rule_id)
            e["last"] = max(e["last"], aware(a.created_at))
        for ip in ips_of(a):
            e = ips.setdefault(ip, {"ip": ip, "alerts": 0, "severity": 0, "tools": set(), "rules": set()})
            e["alerts"] += 1
            e["severity"] = max(e["severity"], a.severity)
            e["tools"].update(tools_of(a))
            e["rules"].add(a.rule_id)

    def ranked(items: list[dict]) -> list[dict]:
        items.sort(key=lambda e: (-e["alerts"], -e["severity"]))
        out = []
        for e in items[:top]:
            row = {**e, "severity": severity_name(e["severity"]), "tools": sorted(e["tools"]),
                   "rules": len(e["rules"])}
            if "tactics" in row:
                row["tactics"] = len(e["tactics"])
            if "last" in row:
                row["last"] = e["last"].isoformat()
            out.append(row)
        return out

    return {
        "considered": len(kept),
        "excluded": len(alerts) - len(kept),
        "unmapped": unmapped,
        "tactics": [{"id": t, "name": name, "alerts": tactic_alerts[t], "exclusive": tactic_exclusive[t],
                     "rules": len(tactic_detections[t]), "entities": len(tactic_entities[t])}
                    for t, name in TACTICS.items()],
        "techniques": [{"id": t, "name": TECHNIQUES.get(t, ("", ()))[0], "alerts": n,
                        "rules": sorted(technique_rules[t]),
                        "tactics": [TACTICS.get(x, x) for x in TECHNIQUES.get(t, ("", ()))[1]]}
                       for t, n in technique_alerts.most_common(20)],
        "hosts": ranked([e for e in entities.values() if e["kind"] == "host"]),
        "accounts": ranked([e for e in entities.values() if e["kind"] == "user"]),
        "ips": ranked(list(ips.values())),
        "method": [
            "Alertes créées pendant la période, **hors faux positifs** et hors alertes calculées (UC-43, UC-44, UC-61, "
            f"qui reprennent d'autres alertes) : {len(kept)} alerte(s) retenue(s), {len(alerts) - len(kept)} écartée(s).",
            "Tactiques d'une alerte : celles des techniques MITRE de sa règle (page Règles), sinon les étiquettes "
            f"fournies par l'outil. {unmapped} alerte(s) retenue(s) sans tactique connue.",
            "Une technique peut relever de plusieurs tactiques (ex. T1078 « Comptes valides » : accès initial, "
            "persistance, élévation, contournement) : une telle alerte compte dans **chacune** de ses tactiques "
            "possibles. La colonne « certaines » ne compte que les alertes dont c'est l'unique tactique possible ; "
            "c'est le chiffre à retenir pour dire « cette tactique a été observée ».",
            "Règles : nombre de règles distinctes ayant produit ces alertes ; entités : machines et comptes "
            "distincts cités.",
            "Machines et comptes : cités par l'alerte (entité, machines d'un regroupement, événement déclencheur), "
            "noms unifiés (nom court/complet, domaine) ; comptes système et comptes machine (finissant par $) "
            "exclus. Une alerte compte une fois par entité citée.",
            "IP : adresses **publiques** citées par l'alerte (adresses internes et réservées exclues).",
        ],
    }
