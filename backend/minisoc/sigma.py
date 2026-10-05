"""Import de règles Sigma (format ouvert de règles de détection) vers le moteur du Mini-SOC.

Principe : une règle n'est convertie que si **tous** ses champs correspondent à des données réellement collectées.
Une conversion approximative produirait de fausses alertes (champ ignoré dans une sélection) ou en masquerait de
vraies (champ ignoré dans un filtre d'exclusion) : la règle est alors refusée, avec la raison.

Pris en charge :
- sources : journaux de sécurité Windows (NXLog), Microsoft 365, pare-feu ; la télémétrie des processus (Sysmon,
  création de processus, registre…) n'est pas collectée — elle relève de l'EDR (HarfangLab) ;
- sélections (dictionnaires, listes de dictionnaires, mots-clés), conditions `and`, `or`, `not`, parenthèses,
  `1 of …`, `all of …`, `them` ;
- modificateurs `contains`, `startswith`, `endswith`, `all`, `cidr`, `gt`, `gte`, `lt`, `lte` ; jokers `*` en
  début ou fin de valeur. Comparaisons insensibles à la casse, comme le prévoit Sigma.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from minisoc.ecs import FIELDS, INT_COLUMNS
from minisoc.frameworks import TECHNIQUE_RE
from minisoc.rules.model import Rule, RuleError

LEVELS = {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}

# Champs Sigma → champ ECS du Mini-SOC (clés en minuscules)
COMMON = {
    "src_ip": "source.ip",
    "sourceip": "source.ip",
    "sourceaddress": "source.ip",
    "ipaddress": "source.ip",
    "clientaddress": "source.ip",
    "clientip": "source.ip",
    "src": "source.ip",
    "dst_ip": "destination.ip",
    "destinationip": "destination.ip",
    "destaddress": "destination.ip",
    "destinationaddress": "destination.ip",
    "dst": "destination.ip",
    "dst_port": "destination.port",
    "destinationport": "destination.port",
    "destport": "destination.port",
    "src_port": "source.port",
    "sourceport": "source.port",
    "computer": "host.name",
    "computername": "host.name",
    "workstationname": "host.name",
    "workstation": "host.name",
    "hostname": "host.name",
}
WINDOWS = {
    **COMMON,
    "targetusername": "user.name",
    "username": "user.name",
    "accountname": "user.name",
    "samaccountname": "user.name",
    "membername": "user.name",
}
M365 = {
    **COMMON,
    "operation": "event.action",
    "userid": "user.name",
    "userprincipalname": "user.name",
    "user": "user.name",
}
FIREWALL = {**COMMON, "action": "event.action", "username": "user.name"}

# logsource → (module du Mini-SOC, correspondance des champs) ; None : refus avec l'explication
UNSUPPORTED_CATEGORIES = {
    "process_creation",
    "process_access",
    "process_tampering",
    "image_load",
    "driver_load",
    "file_event",
    "file_access",
    "file_change",
    "file_delete",
    "file_rename",
    "registry_event",
    "registry_add",
    "registry_set",
    "registry_delete",
    "network_connection",
    "dns_query",
    "pipe_created",
    "create_remote_thread",
    "create_stream_hash",
    "wmi_event",
    "ps_script",
    "ps_module",
    "ps_classic_start",
    "sysmon",
    "clipboard_capture",
}


class SigmaError(ValueError):
    pass


@dataclass
class Conversion:
    ok: bool
    title: str = ""
    sigma_id: str = ""
    level: str = ""
    rule: dict | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    original: str = ""


def _logsource(ls: dict) -> tuple[str, dict[str, str]]:
    product = str(ls.get("product") or "").lower()
    category = str(ls.get("category") or "").lower()
    service = str(ls.get("service") or "").lower()
    if category in UNSUPPORTED_CATEGORIES or service == "sysmon":
        raise SigmaError(
            f"source « {category or service} » : télémétrie des processus, fichiers ou registre non collectée par le "
            "Mini-SOC (elle relève de l'EDR HarfangLab, qui applique déjà les règles Sigma de ce type)"
        )
    if product == "windows":
        if service not in ("security", "system", ""):
            raise SigmaError(f"journal Windows « {service} » non collecté (seuls Sécurité et Système le sont)")
        return "windows", WINDOWS
    if product in ("m365", "microsoft365", "azure", "azuread", "entra", "office365"):
        return "m365", M365
    if category == "firewall":
        return "", FIREWALL
    raise SigmaError(f"source non collectée par le Mini-SOC : {product or '?'} / {category or service or '?'}")


def _value_filter(ecs: str, modifiers: list[str], value: Any) -> dict:
    """Une valeur Sigma (avec modificateurs) → filtre Mini-SOC sur un champ."""
    col = FIELDS[ecs]
    if value is None:
        return {ecs: {"exists": False}}
    if any(m in modifiers for m in ("gt", "gte", "lt", "lte")):
        op = next(m for m in modifiers if m in ("gt", "gte", "lt", "lte"))
        return {ecs: {op: value}}
    if "cidr" in modifiers:
        return {ecs: {"cidr": str(value)}}
    text = str(value)
    if col in INT_COLUMNS:
        try:
            return {ecs: {"eq": int(text)}}
        except ValueError:
            raise SigmaError(f"valeur numérique attendue pour {ecs} : {text}") from None
    for mod in ("contains", "startswith", "endswith"):
        if mod in modifiers:
            return {ecs: {mod: text}}
    # Jokers Sigma en début / fin de valeur
    inner = text.strip("*")
    if "*" in inner or "?" in text:
        raise SigmaError(f"joker au milieu d'une valeur non pris en charge : {text}")
    if text.startswith("*") and text.endswith("*") and len(text) > 1:
        return {ecs: {"contains": inner}}
    if text.endswith("*"):
        return {ecs: {"startswith": inner}}
    if text.startswith("*"):
        return {ecs: {"endswith": inner}}
    return {ecs: {"ieq": text}}


def _field_filter(key: str, values: Any, mapping: dict[str, str], module: str) -> dict:
    name, *modifiers = key.split("|")
    modifiers = [m.lower() for m in modifiers]
    unsupported = [
        m for m in modifiers if m not in ("contains", "startswith", "endswith", "all", "cidr", "gt", "gte", "lt", "lte")
    ]
    if unsupported:
        raise SigmaError(f"modificateur non pris en charge : {'|'.join(unsupported)} (champ {name})")
    values = values if isinstance(values, list) else [values]
    if name.lower() == "eventid":
        if module != "windows":
            raise SigmaError("EventID n'a de sens que pour les journaux Windows")
        ids = [f"Windows {int(v)}" for v in values]
        return {"rule.name": {"in": ids}} if len(ids) > 1 else {"rule.name": {"eq": ids[0]}}
    ecs = mapping.get(name.lower())
    if not ecs:
        raise SigmaError(f"champ non collecté : {name}")
    parts = [_value_filter(ecs, modifiers, v) for v in values]
    if len(parts) == 1:
        return parts[0]
    return {"all" if "all" in modifiers else "any": parts}


def _selection(sel: Any, mapping: dict[str, str], module: str) -> dict:
    if isinstance(sel, dict):
        parts = [_field_filter(k, v, mapping, module) for k, v in sel.items()]
        return parts[0] if len(parts) == 1 else {"all": parts}
    if isinstance(sel, list) and sel and all(isinstance(x, dict) for x in sel):
        parts = [_selection(x, mapping, module) for x in sel]
        return parts[0] if len(parts) == 1 else {"any": parts}
    if isinstance(sel, list) and sel:  # mots-clés : texte du message
        parts = [{"message": {"contains": str(k).strip("*")}} for k in sel]
        return parts[0] if len(parts) == 1 else {"any": parts}
    raise SigmaError("sélection vide ou mal formée")


_COND_TOKEN = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\d+\s+of\b|all\s+of\b|[\w*]+)", re.I)


def _condition(text: str, selections: dict[str, dict]) -> dict:
    tokens = [t.strip() for t in _COND_TOKEN.findall(text) if t.strip()]
    if "|" in text:
        raise SigmaError("conditions d'agrégation Sigma (« | count() ») non prises en charge")
    pos = 0

    def peek() -> str | None:
        return tokens[pos].lower() if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def names(pattern: str) -> list[str]:
        if pattern.lower() == "them":
            found = list(selections)
        else:
            found = [n for n in selections if fnmatch.fnmatchcase(n, pattern)]
        if not found:
            raise SigmaError(f"aucune sélection ne correspond à « {pattern} »")
        return found

    def primary() -> dict:
        word = peek()
        if word is None:
            raise SigmaError("condition incomplète")
        if word == "not":
            take()
            return {"not": primary()}
        if word == "(":
            take()
            inner = expression()
            if peek() != ")":
                raise SigmaError("parenthèse fermante manquante dans la condition")
            take()
            return inner
        quantifier = take()
        if re.match(r"^(\d+|all)\s+of$", quantifier, re.I):
            group = [selections[n] for n in names(take())]
            if len(group) == 1:
                return group[0]
            return {"all": group} if quantifier.lower().startswith("all") else {"any": group}
        if quantifier not in selections:
            raise SigmaError(f"sélection inconnue dans la condition : {quantifier}")
        return selections[quantifier]

    def conjunction() -> dict:
        parts = [primary()]
        while peek() == "and":
            take()
            parts.append(primary())
        return parts[0] if len(parts) == 1 else {"all": parts}

    def expression() -> dict:
        parts = [conjunction()]
        while peek() == "or":
            take()
            parts.append(conjunction())
        return parts[0] if len(parts) == 1 else {"any": parts}

    result = expression()
    if pos != len(tokens):
        raise SigmaError(f"condition incomprise : {text}")
    return result


def _rule_id(doc: dict) -> str:
    base = str(doc.get("id") or doc.get("title") or "")
    return "SIGMA-" + hashlib.sha256(base.encode()).hexdigest()[:8].upper()


def convert(doc: dict, original: str = "") -> Conversion:
    title = str(doc.get("title") or "Règle Sigma sans titre")
    result = Conversion(
        ok=False, title=title, sigma_id=str(doc.get("id") or ""), level=str(doc.get("level") or ""), original=original
    )
    try:
        if not isinstance(doc.get("detection"), dict):
            raise SigmaError("section « detection » absente")
        module, mapping = _logsource(doc.get("logsource") or {})
        detection = dict(doc["detection"])
        condition = detection.pop("condition", None)
        detection.pop("timeframe", None)
        if not condition:
            raise SigmaError("condition absente")
        selections = {name: _selection(sel, mapping, module) for name, sel in detection.items()}
        conditions = condition if isinstance(condition, list) else [condition]
        converted = [_condition(str(c), selections) for c in conditions]
        flt = converted[0] if len(converted) == 1 else {"any": converted}
        if module:
            flt = {"all": [{"event.module": {"eq": module}}, flt]}
        severity = LEVELS.get(str(doc.get("level") or "medium").lower(), "medium")
        mitre = sorted({t[7:].upper() for t in doc.get("tags") or [] if str(t).lower().startswith("attack.t")})
        mitre = [t for t in mitre if TECHNIQUE_RE.match(t)]
        notes = []
        if doc.get("description"):
            notes.append(str(doc["description"]).strip())
        fps = doc.get("falsepositives") or []
        if fps:
            notes.append("Faux positifs possibles : " + "; ".join(str(f) for f in fps))
        refs = [str(r) for r in doc.get("references") or []][:3]
        source = f"Règle Sigma « {title} »" + (f" ({doc['author']})" if doc.get("author") else "")
        group_by = ["source.ip"] if not module else ["host.name", "user.name"]
        rule = {
            "id": _rule_id(doc),
            "name": title[:200],
            "type": "match",
            "severity": severity,
            "title": f"{title[:150]} ({{host.name|user.name|source.ip}})",
            "description": " ".join([*notes, source + ".", *(f"Réf. : {r}" for r in refs)])[:4000],
            "filter": flt,
            "group_by": group_by,
            "mitre": mitre,
        }
        Rule.from_dict(rule, f"sigma:{rule['id']}")  # validation complète par le moteur
        if severity == "info":
            result.warnings.append("niveau « informational » : la règle ne créera que des alertes de sévérité info")
        if str(doc.get("status") or "").lower() in ("experimental", "test"):
            result.warnings.append(
                f"règle au statut « {doc['status']} » : la rejouer sur l'historique avant de l'activer"
            )
        result.ok, result.rule = True, rule
    except (SigmaError, RuleError) as exc:
        result.errors.append(str(exc))
    return result


def convert_text(text: str) -> list[Conversion]:
    """Un ou plusieurs documents YAML Sigma (séparés par « --- »)."""
    try:
        docs = [d for d in yaml.safe_load_all(text) if d]
    except yaml.YAMLError as exc:
        raise SigmaError(f"YAML illisible : {str(exc)[:200]}") from None
    if not docs:
        raise SigmaError("aucune règle trouvée")
    if len(docs) > 200:
        raise SigmaError("200 règles au plus par import")
    out = []
    for doc in docs:
        if not isinstance(doc, dict):
            out.append(Conversion(ok=False, errors=["document YAML qui n'est pas une règle"]))
            continue
        out.append(convert(doc, yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)))
    return out
