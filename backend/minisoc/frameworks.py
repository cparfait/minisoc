"""Référentiel MITRE ATT&CK (Enterprise) : techniques citées par les règles et tactiques associées.

Extrait volontairement limité aux techniques pertinentes pour les sources raccordées ; une technique absente
d'ici reste acceptée dans une règle (identifiant valide), seulement sans libellé.
Source : https://attack.mitre.org/ (contenu sous licence MITRE, réutilisation autorisée avec attribution).
"""

from __future__ import annotations

import re

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Ordre de la chaîne d'attaque (matrice Enterprise)
TACTICS: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0001": "Accès initial",
    "TA0002": "Exécution",
    "TA0003": "Persistance",
    "TA0004": "Élévation de privilèges",
    "TA0005": "Contournement des défenses",
    "TA0006": "Accès aux identifiants",
    "TA0007": "Découverte",
    "TA0008": "Mouvement latéral",
    "TA0009": "Collecte",
    "TA0011": "Commande et contrôle",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Technique -> (nom, tactiques)
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1595": ("Active Scanning", ("TA0043",)),
    "T1133": ("External Remote Services", ("TA0001", "TA0003")),
    "T1190": ("Exploit Public-Facing Application", ("TA0001",)),
    "T1566": ("Phishing", ("TA0001",)),
    "T1078": ("Valid Accounts", ("TA0001", "TA0003", "TA0004", "TA0005")),
    "T1078.002": ("Valid Accounts: Domain Accounts", ("TA0001", "TA0003", "TA0004", "TA0005")),
    "T1078.004": ("Valid Accounts: Cloud Accounts", ("TA0001", "TA0003", "TA0004", "TA0005")),
    "T1204": ("User Execution", ("TA0002",)),
    "T1204.002": ("User Execution: Malicious File", ("TA0002",)),
    "T1059": ("Command and Scripting Interpreter", ("TA0002",)),
    "T1098": ("Account Manipulation", ("TA0003", "TA0004")),
    "T1098.003": ("Account Manipulation: Additional Cloud Roles", ("TA0003", "TA0004")),
    "T1136": ("Create Account", ("TA0003",)),
    "T1562": ("Impair Defenses", ("TA0005",)),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ("TA0005",)),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", ("TA0005",)),
    "T1110": ("Brute Force", ("TA0006",)),
    "T1110.001": ("Brute Force: Password Guessing", ("TA0006",)),
    "T1110.003": ("Brute Force: Password Spraying", ("TA0006",)),
    "T1110.004": ("Brute Force: Credential Stuffing", ("TA0006",)),
    "T1003": ("OS Credential Dumping", ("TA0006",)),
    "T1558": ("Steal or Forge Kerberos Tickets", ("TA0006",)),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", ("TA0006",)),
    "T1621": ("Multi-Factor Authentication Request Generation", ("TA0006",)),
    "T1528": ("Steal Application Access Token", ("TA0006",)),
    "T1087": ("Account Discovery", ("TA0007",)),
    "T1021": ("Remote Services", ("TA0008",)),
    "T1071": ("Application Layer Protocol", ("TA0011",)),
    "T1114.003": ("Email Collection: Email Forwarding Rule", ("TA0009",)),
    "T1041": ("Exfiltration Over C2 Channel", ("TA0010",)),
    "T1485": ("Data Destruction", ("TA0040",)),
    "T1486": ("Data Encrypted for Impact", ("TA0040",)),
    "T1490": ("Inhibit System Recovery", ("TA0040",)),
}


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def describe(technique_id: str) -> dict:
    name, tactics = TECHNIQUES.get(technique_id, ("", ()))
    return {
        "id": technique_id,
        "name": name,
        "tactics": [{"id": t, "name": TACTICS[t]} for t in tactics],
        "url": technique_url(technique_id),
    }


def coverage(rule_techniques: dict[str, list[str]]) -> list[dict]:
    """Par tactique : techniques couvertes et règles correspondantes (règles actives uniquement)."""
    out = []
    for tactic_id, tactic_name in TACTICS.items():
        covered: dict[str, list[str]] = {}
        for rule_id, techniques in rule_techniques.items():
            for tech in techniques:
                if tactic_id in TECHNIQUES.get(tech, ("", ()))[1]:
                    covered.setdefault(tech, []).append(rule_id)
        out.append({
            "id": tactic_id,
            "name": tactic_name,
            "techniques": [{**describe(t), "rules": sorted(r)} for t, r in sorted(covered.items())],
        })
    return out
