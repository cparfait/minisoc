"""Score de risque par machine et par compte, et chaînes d'attaque.

**Score de risque** (7 jours glissants) : chaque détection ajoute des points à chaque machine et chaque compte
qu'elle cite. Une attaque réelle produit souvent plusieurs petits signaux, ignorés un par un : leur cumul alerte.
- une même détection sur une même entité ne compte qu'une fois (les alertes répétées d'une tâche quotidienne ne
  gonflent pas le score) ; une détection répandue (20 machines ou plus) compte moitié moins ;
- points selon la sévérité (faible 3, moyenne 8, haute 20, critique 40) ; hygiène du parc ×0,2, information ×0 ;
- +10 par tactique MITRE supplémentaire (30 au plus) ; criticité de l'inventaire : vitale ×1,5, haute ×1,25,
  basse ×0,75 ; faux positifs exclus.

**Chaîne d'attaque** (24 heures) : au moins 3 tactiques MITRE différentes sur une même entité, dont une étape
avancée (exécution, persistance, élévation, identifiants, mouvement latéral, commande et contrôle, exfiltration,
impact) → alerte critique et, si le réglage est actif, incident créé automatiquement.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from minisoc.detections import WIDESPREAD, alert_detections, detection_key, entity_parts, spread
from minisoc.frameworks import TACTICS, TECHNIQUES
from minisoc.models import Alert
from minisoc.replay import TACTIC_TAGS

RISK_RULE, CHAIN_RULE, DECOY_RULE = "UC-43", "UC-44", "UC-45"
DERIVED_RULES = {RISK_RULE, CHAIN_RULE}  # alertes calculées : n'entrent pas dans le calcul
RISK_WINDOW = timedelta(days=7)
CHAIN_WINDOW = timedelta(hours=24)
SEVERITY_POINTS = {0: 0, 1: 3, 2: 8, 3: 20, 4: 40}
CATEGORY_FACTOR = {"threat": 1.0, "hygiene": 0.2, "info": 0.0}
CRITICALITY_FACTOR = {"vital": 1.5, "high": 1.25, "normal": 1.0, "low": 0.75}
LATE_TACTICS = {"TA0002", "TA0003", "TA0004", "TA0006", "TA0008", "TA0011", "TA0010", "TA0040"}
CHAIN_MIN_TACTICS = 3


def tactics_from_tags(tags: list[str]) -> list[str]:
    """Étiquettes Sigma d'une alerte d'outil (attack.execution, attack.t1059.001…) → tactiques MITRE."""
    out: set[str] = set()
    for tag in tags or []:
        tag = str(tag).lower()
        if not tag.startswith("attack."):
            continue
        name = tag[7:]
        if name in TACTIC_TAGS:
            out.add(TACTIC_TAGS[name])
        elif name.startswith("t"):
            out.update(TECHNIQUES.get(name.upper(), ("", ()))[1])
    return sorted(out)


def tactics_from_raw(raw: str) -> list[str]:
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    tags = data.get("tags") if isinstance(data, dict) else None
    return tactics_from_tags(tags if isinstance(tags, list) else [])


def alert_tactics(alert: Alert, rule_mitre: dict[str, list[str]]) -> set[str]:
    """Tactiques d'une alerte : techniques de sa règle, sinon étiquettes de l'outil (details.tactics)."""
    found = set((alert.details or {}).get("tactics") or [])
    for technique in rule_mitre.get(alert.rule_id, []):
        found.update(TECHNIQUES.get(technique, ("", ()))[1])
    return found


def entities_of(alert: Alert) -> set[tuple[str, str]]:
    """(host|user, nom) cités par l'alerte : entité, entités regroupées, événement déclencheur."""
    out: set[tuple[str, str]] = set()
    for _, _, host, _ in alert_detections(alert):
        if host:
            out.add(("host", host))
    parts = entity_parts(alert.entity_key)
    if parts.get("host.name"):
        out.add(("host", parts["host.name"]))
    if parts.get("user.name"):
        out.add(("user", parts["user.name"]))
    sample = (alert.details or {}).get("sample") or {}
    for kind, key in (("host", "host.name"), ("user", "user.name")):
        value = str(sample.get(key) or "").strip()
        if value and value not in ("-", "?"):
            out.add((kind, value))
    return {(k, v) for k, v in out if v and not v.endswith("$") and not (k == "user" and builtin_account(v))}


# Comptes du système : ils ne désignent pas une personne et regrouperaient des machines sans rapport
BUILTIN_ACCOUNTS = {"system", "network service", "local service", "localsystem", "anonymous logon", "nt authority",
                    "autorite nt", "root", "nobody", "www-data", "daemon"}


def builtin_account(name: str) -> bool:
    from minisoc.accounts import normalize

    return normalize(name) in BUILTIN_ACCOUNTS


def domains_of(alerts: list[Alert]) -> set[str]:
    """Noms de domaine Windows vus dans les comptes (« MAIRIE\\j.dupont » → « chatillon ») : une ancienne alerte qui
    porte le domaine à la place du compte ne doit pas créer un faux « compte » à risque."""
    found = set()
    for alert in alerts:
        user = str(((alert.details or {}).get("sample") or {}).get("user.name") or "")
        if "\\" in user:
            found.add(user.split("\\", 1)[0].strip().lower())
    return found


def _norm(kind: str, name: str) -> str:
    from minisoc.assets import key_for

    return key_for("host" if kind == "host" else "account", name)


def _targets(alert: Alert, storm: bool) -> list[tuple[str, str, str, str]]:
    """(type, nom, détection, libellé) : pour un regroupement anti-tempête, chaque machine avec SA détection (elle se
    confond alors avec l'alerte individuelle de la même détection, au lieu de compter deux fois)."""
    if storm:
        return [("host", host, f"{module}|{name}".lower(), f"{name} (regroupement n° {alert.id})")
                for module, name, host, _ in alert_detections(alert) if host]
    detection = _detection(alert)
    return [(kind, name, detection, alert.title) for kind, name in entities_of(alert)]


def _detection(alert: Alert) -> str:
    found = alert_detections(alert)
    return f"{found[0][0]}|{found[0][1]}".lower() if found else alert.rule_id


@dataclass
class EntityRisk:
    kind: str
    name: str
    score: float = 0.0
    tactics: set[str] = field(default_factory=set)
    contributions: dict[str, dict] = field(default_factory=dict)  # détection -> {points, alert_id, title…}

    def to_dict(self) -> dict:
        items = sorted(self.contributions.values(), key=lambda c: -c["points"])
        return {
            "kind": self.kind,
            "name": self.name,
            "score": round(self.score),
            "tactics": [{"id": t, "name": TACTICS.get(t, t)} for t in sorted(self.tactics, key=_tactic_order)],
            "contributors": items,
        }


def _tactic_order(tactic: str) -> int:
    order = list(TACTICS)
    return order.index(tactic) if tactic in order else 99


def compute_risk(
    alerts: list[Alert], rule_mitre: dict[str, list[str]], criticality=None, now: datetime | None = None
) -> dict[tuple[str, str], EntityRisk]:
    """`criticality(kind, name)` → criticité de l'inventaire (ou None)."""
    now = now or datetime.now(timezone.utc)
    machines = spread([a for a in alerts if a.status in ("new", "in_progress", "waiting")])
    domains = domains_of(alerts)
    out: dict[tuple[str, str], EntityRisk] = {}
    for alert in alerts:
        last = alert.last_seen if alert.last_seen.tzinfo else alert.last_seen.replace(tzinfo=timezone.utc)
        if alert.rule_id in DERIVED_RULES or alert.status == "false_positive" or now - last > RISK_WINDOW:
            continue
        category = (alert.details or {}).get("category") or "threat"
        points = SEVERITY_POINTS.get(alert.severity, 0) * CATEGORY_FACTOR.get(category, 1.0)
        found = alert_detections(alert)
        if found and max(machines.get(detection_key(m, d), 0) for m, d, _, _ in found) >= WIDESPREAD:
            points *= 0.5
        if points <= 0:
            continue
        # Regroupement anti-tempête : plusieurs machines mêlées, ses tactiques ne sont attribuables à aucune
        storm = bool((alert.details or {}).get("storm"))
        tactics = alert_tactics(alert, rule_mitre) if category == "threat" and not storm else set()
        for kind, name, detection, label in _targets(alert, storm):
            key = (kind, _norm(kind, name))
            if kind == "user" and key[1] in domains:
                continue
            risk = out.setdefault(key, EntityRisk(kind, name))
            current = risk.contributions.get(detection)
            if current is None or points > current["points"]:
                risk.contributions[detection] = {
                    "points": round(points, 1),
                    "alert_id": alert.id,
                    "title": label,
                    "rule_id": alert.rule_id,
                    "severity": alert.severity,
                    "category": category,
                    "last_seen": last.isoformat(),
                }
            risk.tactics |= tactics
    for (kind, _), risk in out.items():
        base = sum(c["points"] for c in risk.contributions.values())
        bonus = min(30, 10 * max(0, len(risk.tactics) - 1))
        factor = CRITICALITY_FACTOR.get((criticality(kind, risk.name) if criticality else None) or "normal", 1.0)
        risk.score = (base + bonus) * factor
    return out


@dataclass
class Chain:
    kind: str
    name: str
    steps: list[dict]  # {alert_id, title, tactics, ts}
    tactics: list[str]

    @property
    def alert_ids(self) -> list[int]:
        return [s["alert_id"] for s in self.steps]


def find_chains(alerts: list[Alert], rule_mitre: dict[str, list[str]], now: datetime | None = None) -> list[Chain]:
    """Entités ayant enchaîné au moins 3 tactiques (dont une étape avancée) en 24 heures."""
    now = now or datetime.now(timezone.utc)
    by_entity: dict[tuple[str, str], list[tuple[Alert, set[str]]]] = defaultdict(list)
    names: dict[tuple[str, str], str] = {}
    domains = domains_of(alerts)
    for alert in alerts:
        if (alert.details or {}).get("storm"):
            continue  # regroupement anti-tempête : étapes de machines différentes, pas une chaîne
        last = alert.last_seen if alert.last_seen.tzinfo else alert.last_seen.replace(tzinfo=timezone.utc)
        category = (alert.details or {}).get("category") or "threat"
        if alert.rule_id in DERIVED_RULES or alert.status == "false_positive" or category != "threat":
            continue
        if now - last > CHAIN_WINDOW:
            continue
        tactics = alert_tactics(alert, rule_mitre)
        if not tactics:
            continue
        for kind, name in entities_of(alert):
            key = (kind, _norm(kind, name))
            if kind == "user" and key[1] in domains:
                continue
            by_entity[key].append((alert, tactics))
            names.setdefault(key, name)
    chains = []
    for key, items in by_entity.items():
        tactics = set().union(*(t for _, t in items))
        if len(tactics) < CHAIN_MIN_TACTICS or not tactics & LATE_TACTICS:
            continue
        items.sort(key=lambda it: it[0].first_seen)
        steps = [
            {
                "alert_id": a.id,
                "title": a.title,
                "ts": a.first_seen.isoformat(),
                "tactics": [TACTICS.get(t, t) for t in sorted(t_, key=_tactic_order)],
            }
            for a, t_ in items
        ]
        chains.append(Chain(key[0], names[key], steps, [TACTICS.get(t, t) for t in sorted(tactics, key=_tactic_order)]))
    return chains
