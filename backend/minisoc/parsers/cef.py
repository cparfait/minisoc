"""Messages au format CEF (Common Event Format) : Vectra, Varonis et la plupart des outils du marché.

CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|cle=valeur cle2=valeur avec espaces
"""

from __future__ import annotations

import re
from datetime import datetime

from minisoc.ecs import Event
from minisoc.parsers.common import first, parse_ts

_HEADER_SPLIT = re.compile(r"(?<!\\)\|")
_EXT = re.compile(r"(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|\s*$)")

_TEXT_SEVERITY = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "very-high": 4, "very high": 4, "critical": 4}

_KNOWN_MODULES = {"vectra": "vectra", "varonis": "varonis", "sophos": "sophos_xgs", "crowdsec": "crowdsec"}

_CATEGORY_BY_MODULE = {"vectra": "intrusion_detection", "varonis": "file"}


def parse_cef(text: str, received: datetime, peer: str = "") -> Event | None:
    start = text.find("CEF:")
    if start < 0:
        return None
    parts = _HEADER_SPLIT.split(text[start + 4 :], maxsplit=7)
    if len(parts) < 8:
        return None
    _version, vendor, product, _dev_version, signature, name, severity, extension = (
        _unescape_header(p) for p in parts
    )
    ext = {key: _unescape_value(value) for key, value in _EXT.findall(extension)}
    module = _module(vendor, product)

    fields = dict(
        ts=parse_ts(first(ext, "rt", "end", "start"), received),
        module=module,
        kind="alert",
        category=_CATEGORY_BY_MODULE.get(module, "intrusion_detection"),
        action=first(ext, "act", "cat", default=signature).lower(),
        outcome=_outcome(first(ext, "outcome")),
        severity=_severity(severity),
        source_ip=first(ext, "src", "c6a2"),
        source_port=first(ext, "spt", default="0"),
        destination_ip=first(ext, "dst", "c6a3"),
        destination_port=first(ext, "dpt", default="0"),
        user_name=first(ext, "suser", "duser"),
        host_name=first(ext, "shost", "dhost", "dvchost"),
        host_ip=first(ext, "dvc"),
        rule_name=name,
        threat_name=first(ext, "cs1", default=signature),
        file_path=first(ext, "filePath", "fname"),
        observer=first(ext, "dvchost", default=peer or vendor),
        reference=_console_url(ext),
        message=first(ext, "msg", default=name),
        raw=text,
    )
    if module == "vectra":
        _vectra(fields, ext, signature)
    elif module == "varonis":
        _varonis(fields, ext)
    return Event(**fields)


def _labeled(ext: dict, label: str) -> str:
    """Valeur d'un champ personnalisé CEF (csN, cnN, flexNumberN, flexStringN) d'après son libellé."""
    for prefix in ("cs", "cn", "flexNumber", "flexString", "cfp"):
        for i in range(1, 7):
            if ext.get(f"{prefix}{i}Label", "").strip().lower() == label:
                return ext.get(f"{prefix}{i}", "")
    return ""


def _console_url(ext: dict) -> str:
    """Lien vers l'outil d'origine : premier champ personnalisé dont le libellé contient « url »."""
    for prefix in ("cs", "flexString"):
        for i in range(1, 7):
            value = ext.get(f"{prefix}{i}", "")
            if "url" in ext.get(f"{prefix}{i}Label", "").lower() and value.lower().startswith("http"):
                return value
    return ext.get("requestUrl", "") if ext.get("requestUrl", "").lower().startswith("http") else ""


def _int(value: str) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return -1


def _vectra(fields: dict, ext: dict, signature: str) -> None:
    """Vectra : scores de menace et de certitude (0-100) → sévérité selon les quadrants de la console Vectra
    (critique : les deux ≥ 50 ; haute : menace ≥ 50 ; moyenne : certitude ≥ 50 ; faible sinon)."""
    threat, certainty = _int(_labeled(ext, "threat")), _int(_labeled(ext, "certainty"))
    category = ext.get("cat", "")
    if threat >= 0 and certainty >= 0:
        high_threat, high_certainty = threat >= 50, certainty >= 50
        fields["severity"] = 4 if high_threat and high_certainty else 3 if high_threat else 2 if high_certainty else 1
        fields["message"] = f"{fields['message']} (menace {threat}, certitude {certainty})"
    if signature in ("hsc", "asc") or "scoring" in category.lower():
        account = signature == "asc" or "account" in category.lower()
        fields["action"] = "account_scoring" if account else "host_scoring"
        if fields["action"] == "account_scoring":
            fields["user_name"] = first(ext, "suser", "duser", "shost")
    fields["threat_name"] = category or fields["threat_name"]


RANSOMWARE = re.compile(r"ransom|encrypt|chiffr", re.I)


def _varonis(fields: dict, ext: dict) -> None:
    """Varonis : compte « DOMAINE\\utilisateur » ramené à l'identifiant ; alertes de rançongiciel signalées comme
    telles (règle UC-06)."""
    user = fields.get("user_name") or ""
    if "\\" in user:
        fields["user_name"] = user.rsplit("\\", 1)[1]
    text = f"{fields.get('rule_name', '')} {fields.get('message', '')} {_labeled(ext, 'rule name')}"
    if RANSOMWARE.search(text):
        fields["action"] = "ransomware_detected"
        fields["severity"] = max(int(fields.get("severity") or 0), 4)


def _module(vendor: str, product: str) -> str:
    descr = f"{vendor} {product}".lower()
    for pattern, module in _KNOWN_MODULES.items():
        if pattern in descr:
            return module
    slug = re.sub(r"[^a-z0-9]+", "_", descr).strip("_")
    return slug or "cef"


def _severity(value: str) -> int:
    value = value.strip().lower()
    if value.isdigit():
        number = int(value)
        if number >= 9:
            return 4
        if number >= 7:
            return 3
        if number >= 4:
            return 2
        return 1 if number >= 1 else 0
    return _TEXT_SEVERITY.get(value, 2)


def _outcome(value: str) -> str:
    value = value.lower()
    if value in {"failure", "failed", "blocked"}:
        return "failure"
    if value in {"success", "succeeded", "allowed"}:
        return "success"
    return ""


def _unescape_header(value: str) -> str:
    return value.replace("\\|", "|").replace("\\\\", "\\")


def _unescape_value(value: str) -> str:
    return value.strip().replace("\\=", "=").replace("\\n", "\n").replace("\\\\", "\\")
