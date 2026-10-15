"""Événement normalisé. Les noms de champs suivent Elastic Common Schema (ECS)."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone

SEVERITY_NAMES = ("info", "low", "medium", "high", "critical")
SEVERITY_BY_NAME = {name: level for level, name in enumerate(SEVERITY_NAMES)}

# Champ ECS -> attribut de Event (= colonne ClickHouse). Seuls ces champs sont utilisables dans les règles.
FIELDS: dict[str, str] = {
    "@timestamp": "ts",
    "event.id": "event_id",
    "event.module": "module",
    "event.kind": "kind",
    "event.category": "category",
    "event.action": "action",
    "event.outcome": "outcome",
    "event.reason": "reason",
    "event.severity": "severity",
    "event.reference": "reference",
    "source.ip": "source_ip",
    "source.geo.country_iso_code": "source_country",
    "source.as.organization.name": "source_as",
    "source.port": "source_port",
    "destination.ip": "destination_ip",
    "destination.port": "destination_port",
    "user.name": "user_name",
    "user.key": "user_key",  # compte unifié : identifiant Windows quelle que soit la forme reçue (minisoc/identity.py)
    "user.roles": "user_roles",  # compte sensible : « admin », « service » ou « admin,service » (minisoc/accounts.py)
    "host.name": "host_name",
    "host.key": "host_key",  # machine unifiée : nom court, adresse IP remplacée par le nom quand il est connu
    "host.ip": "host_ip",
    "network.service": "network_service",
    "rule.name": "rule_name",
    "threat.name": "threat_name",
    "threat.intel": "intel",  # renseignement : ex. « crowdsec:crowdsecurity/ssh-bf » si l'IP source est bannie
    "file.path": "file_path",
    "dns.question.name": "dns_query",  # nom demandé au DNS (journaux des contrôleurs de domaine)
    "dns.question.registered_domain": "dns_domain",  # domaine enregistré (exemple.fr pour www.exemple.fr)
    "observer.name": "observer",
    "message": "message",
}
INT_COLUMNS = frozenset({"severity", "source_port", "destination_port"})

# Le contenu des journaux est contrôlé par l'attaquant : longueur bornée, caractères nuls retirés.
_LIMITS = {"message": 4096, "raw": 16384}
_DEFAULT_LIMIT = 512


def severity_name(level: int) -> str:
    return SEVERITY_NAMES[max(0, min(4, level))]


@dataclass
class Event:
    ts: datetime
    module: str
    kind: str = "event"  # event | alert (alerte native d'un outil)
    category: str = ""
    action: str = ""
    outcome: str = ""  # success | failure | ""
    reason: str = ""  # motif d'échec normalisé (unknown_user, invalid_credentials, password_expired…)
    severity: int = 0  # 0 info … 4 critical
    source_ip: str = ""
    source_port: int = 0
    source_country: str = ""  # code ISO du pays (GeoIP)
    source_as: str = ""  # opérateur / hébergeur (GeoIP ASN)
    destination_ip: str = ""
    destination_port: int = 0
    user_name: str = ""
    user_key: str = ""  # compte unifié (minisoc/identity.py), ajouté à l'enrichissement
    user_roles: str = ""  # rôle du compte (administrateur, compte de service), ajouté à l'enrichissement
    host_name: str = ""
    host_key: str = ""  # machine unifiée (minisoc/identity.py), ajoutée à l'enrichissement
    host_ip: str = ""
    network_service: str = ""
    rule_name: str = ""
    threat_name: str = ""
    intel: str = ""
    file_path: str = ""
    dns_query: str = ""
    dns_domain: str = ""
    observer: str = ""
    reference: str = ""
    message: str = ""
    raw: str = ""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        if self.ts.tzinfo is None:
            self.ts = self.ts.replace(tzinfo=timezone.utc)
        else:
            self.ts = self.ts.astimezone(timezone.utc)
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(value, str):
                cleaned = value.replace("\x00", "").strip()
                setattr(self, f.name, cleaned[: _LIMITS.get(f.name, _DEFAULT_LIMIT)])
        self.severity = max(0, min(4, int(self.severity or 0)))
        self.source_port = _port(self.source_port)
        self.destination_port = _port(self.destination_port)

    def get(self, ecs_field: str):
        return getattr(self, FIELDS.get(ecs_field, ecs_field), None)

    def ecs(self) -> dict[str, object]:
        return {name: getattr(self, col) for name, col in FIELDS.items()}

    def to_row(self) -> dict:
        return asdict(self)


COLUMNS: tuple[str, ...] = tuple(f.name for f in fields(Event))


def _port(value) -> int:
    try:
        port = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return port if 0 <= port <= 65535 else 0
