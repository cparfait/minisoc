"""Qualification automatique des alertes d'authentification : attaque, erreur d'utilisateur ou à vérifier.

Beaucoup d'échecs de connexion ne sont pas des attaques : mot de passe expiré, téléphone qui réessaie avec
un ancien mot de passe, faute de frappe suivie d'une connexion réussie. La qualification s'appuie sur :
  - le motif d'échec (compte inexistant, mot de passe erroné, expiré, compte verrouillé…) ;
  - l'historique : l'IP s'est-elle déjà connectée avec succès sur ce compte (« IP habituelle ») ?
  - le profil : un seul compte visé, ou plusieurs (pulvérisation de mots de passe) ?
Chaque verdict est accompagné de ses raisons, affichées dans l'alerte. Un verdict « légitime » abaisse la
sévérité à « faible » : pas de notification immédiate, l'alerte reste consultable.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field

from minisoc.ecs import SEVERITY_BY_NAME
from minisoc.events_store import EventStore
from minisoc.rules.model import Rule

HISTORY_DAYS = 30
RECENT_HOURS = 24  # période de l'attaque, exclue de l'historique « habituel »
ACCOUNT_ISSUES = ("password_expired", "account_locked", "account_disabled")

LOW = SEVERITY_BY_NAME["low"]
MEDIUM = SEVERITY_BY_NAME["medium"]
HIGH = SEVERITY_BY_NAME["high"]
CRITICAL = SEVERITY_BY_NAME["critical"]

LABELS = {
    "attack": "Attaque probable",
    "suspicious": "À vérifier",
    "benign": "Erreur d'utilisateur probable",
}


@dataclass
class Qualification:
    verdict: str  # attack | suspicious | benign
    reasons: list[str] = field(default_factory=list)
    severity: int | None = None  # None = sévérité de la règle

    @property
    def label(self) -> str:
        return LABELS[self.verdict]

    def as_dict(self) -> dict:
        return {**asdict(self), "label": self.label}


# Historique des connexions réussies d'une IP et/ou d'un compte, hors période récente.
_HISTORY = """
SELECT count() AS successes, max(ts) AS last_success, groupUniqArray(10)(user_name) AS users,
       groupUniqArray(10)(source_ip) AS ips
FROM events
WHERE category = 'authentication' AND outcome = 'success'
  AND ts >= now64(3) - INTERVAL {days:UInt32} DAY AND ts < now64(3) - INTERVAL {recent:UInt32} HOUR
  AND {where}
"""

# Profil des échecs récents.
_FAILURES = """
SELECT count() AS failures, uniqExact(user_name) AS users, uniqExact(source_ip) AS ips,
       countIf(reason = 'unknown_user') AS unknown_user,
       countIf(reason IN ('password_expired', 'account_locked', 'account_disabled')) AS account_issue,
       groupUniqArray(10)(user_name) AS sample_users, groupUniqArray(20)(source_ip) AS sample_ips
FROM events
WHERE category = 'authentication' AND outcome = 'failure'
  AND ts >= now64(3) - INTERVAL {recent:UInt32} HOUR AND {where}
"""


class AuthQualifier:
    def __init__(self, store: EventStore) -> None:
        self.store = store

    async def qualify(self, rule: Rule, values: dict[str, object], row: dict,
                      home_countries: tuple[str, ...] = ("FR",)) -> Qualification | None:
        handler = {
            "auth_source_ip": self._source_ip,
            "auth_account": self._account,
            "auth_success_ip": self._success_ip,
            "auth_success_user": self._success_user,
        }.get(rule.qualify)
        if not handler:
            return None
        result = await handler(values, row)
        if rule.qualify != "auth_account":
            ips = [str(values["source.ip"])] if values.get("source.ip") else [
                ip for ip in row.get("sample_ips", []) if ip
            ][:3]
            await self._apply_ip_context(result, ips, home_countries)
        return result

    # --- Contexte des adresses : pays, opérateur, renseignement CrowdSec ---------------------------

    async def _apply_ip_context(self, q: Qualification, ips: list[str], home: tuple[str, ...]) -> None:
        if not ips:
            return
        rows = await self.store.query(
            "SELECT source_ip AS ip, any(source_country) AS country, any(source_as) AS asn, "
            "anyIf(intel, intel != '') AS intel FROM events WHERE source_ip IN {ips:Array(String)} "
            "AND ts >= now64(3) - INTERVAL 24 HOUR GROUP BY source_ip",
            {"ips": ips},
        )
        risky = False
        for r in rows:
            if r["intel"]:
                q.reasons.append(f"{r['ip']} est bannie par CrowdSec ({r['intel'].removeprefix('crowdsec:')})")
                risky = True
            if r["asn"] and is_hosting(r["asn"]):
                q.reasons.append(f"{r['ip']} appartient à un hébergeur ou relais ({r['asn']}) : rarement un agent")
                risky = True
            if r["country"] and r["country"] not in home:
                q.reasons.append(f"{r['ip']} est localisée hors des pays habituels : {r['country']}")
            elif r["country"]:
                q.reasons.append(f"{r['ip']} : {r['country']}" + (f", {r['asn']}" if r["asn"] else ""))
        if risky and q.verdict == "benign":
            q.verdict, q.severity = "suspicious", None
            q.reasons.append("Indices d'attaque malgré l'historique : à vérifier")
        elif risky and q.verdict == "suspicious":
            q.verdict = "attack"

    # --- Requêtes ------------------------------------------------------------------------------

    async def _history(self, where: str, params: dict) -> dict:
        rows = await self.store.query(
            _HISTORY.replace("{where}", where), {**params, "days": HISTORY_DAYS, "recent": RECENT_HOURS}
        )
        return rows[0] if rows else {"successes": 0, "users": [], "ips": []}

    async def _failures(self, where: str, params: dict) -> dict:
        rows = await self.store.query(_FAILURES.replace("{where}", where), {**params, "recent": RECENT_HOURS})
        return rows[0] if rows else {"failures": 0, "users": 0, "ips": 0, "unknown_user": 0, "account_issue": 0}

    # --- UC-01 : nombreux échecs depuis une IP ---------------------------------------------------

    async def _source_ip(self, values: dict, row: dict) -> Qualification:
        ip = str(values.get("source.ip", ""))
        fails = await self._failures("source_ip = {ip:String}", {"ip": ip})
        users = [u for u in fails.get("sample_users", []) if u]
        reasons = [f"{fails['failures']} échecs en 24 h sur {fails['users']} compte(s) : {', '.join(users[:5])}"]

        if fails["users"] >= 3:
            reasons.append("Plusieurs comptes différents depuis la même IP : pulvérisation de mots de passe")
            return Qualification("attack", reasons)
        if fails["failures"] and fails["unknown_user"] / fails["failures"] >= 0.5:
            reasons.append("Majorité d'essais sur des comptes inexistants : énumération de comptes")
            return Qualification("attack", reasons)

        history = await self._history(
            "source_ip = {ip:String} AND user_name IN {users:Array(String)}", {"ip": ip, "users": users}
        )
        if history["successes"]:
            reasons.append(
                f"IP habituelle : {history['successes']} connexion(s) réussie(s) sur ce compte depuis cette IP "
                f"dans les {HISTORY_DAYS} derniers jours"
            )
            if fails["account_issue"]:
                reasons.append("Mot de passe expiré ou compte verrouillé : prévenir l'utilisateur")
            else:
                reasons.append("Probablement un ancien mot de passe enregistré (téléphone, client VPN)")
            return Qualification("benign", reasons, LOW)
        if fails["account_issue"] and fails["account_issue"] / max(fails["failures"], 1) >= 0.5:
            reasons.append("Mot de passe expiré ou compte verrouillé : probablement l'utilisateur légitime")
            return Qualification("benign", reasons, LOW)
        if _is_internal(ip):
            reasons.append("Adresse IP interne")
            return Qualification("suspicious", reasons, MEDIUM)
        reasons.append(
            "Un seul compte visé, depuis une IP jamais vue en connexion réussie : vérifier avec l'utilisateur"
        )
        return Qualification("suspicious", reasons)

    # --- UC-02a : un compte visé depuis de nombreuses IP ------------------------------------------

    async def _account(self, values: dict, row: dict) -> Qualification:
        user = str(values.get("user.name", ""))
        history = await self._history("user_name = {user:String}", {"user": user})
        reasons = [f"Compte visé depuis {row.get('value', '?')} IP différentes : attaque distribuée"]
        if history["successes"]:
            reasons.append("Compte réel et actif : l'attaquant connaît un identifiant valide")
            reasons.append("Vérifier que le MFA est actif sur ce compte ; changer le mot de passe par précaution")
            return Qualification("attack", reasons)
        reasons.append(
            f"Aucune connexion réussie de ce compte depuis {HISTORY_DAYS} jours : compte inexistant ou inactif, "
            "risque plus faible"
        )
        return Qualification("attack", reasons, HIGH)

    # --- UC-03a : connexion réussie depuis une IP qui a cumulé des échecs ------------------------

    async def _success_ip(self, values: dict, row: dict) -> Qualification:
        ip = str(values.get("source.ip", ""))
        users = [u for u in row.get("sample_users", []) if u]
        fails = await self._failures("source_ip = {ip:String}", {"ip": ip})
        reasons = [f"Connexion réussie ({', '.join(users[:3]) or '?'}) après {fails['failures']} échecs depuis {ip}"]
        if fails["users"] >= 3:
            reasons.append(f"Cette IP a essayé {fails['users']} comptes : un mot de passe a probablement été trouvé")
            return Qualification("attack", reasons, CRITICAL)
        history = await self._history(
            "source_ip = {ip:String} AND user_name IN {users:Array(String)}", {"ip": ip, "users": users}
        )
        if history["successes"]:
            reasons.append("IP habituelle de cet utilisateur : probablement une erreur de saisie puis la bonne")
            return Qualification("benign", reasons, LOW)
        reasons.append("IP jamais vue en connexion réussie sur ce compte : confirmer auprès de l'utilisateur")
        return Qualification("suspicious", reasons, CRITICAL)

    # --- UC-03b : connexion réussie sur un compte qui a subi des échecs --------------------------

    async def _success_user(self, values: dict, row: dict) -> Qualification:
        user = str(values.get("user.name", ""))
        success_ips = [ip for ip in row.get("sample_ips", []) if ip]
        fails = await self._failures("user_name = {user:String}", {"user": user})
        # Échecs (tous comptes) depuis les IP de la connexion réussie : ces IP participaient-elles à l'attaque ?
        overlap = await self._failures("source_ip IN {ips:Array(String)}", {"ips": success_ips})
        history = await self._history(
            "user_name = {user:String} AND source_ip IN {ips:Array(String)}", {"user": user, "ips": success_ips}
        )
        usual = bool(history["successes"])
        from_attackers = overlap["users"] >= 2 or (overlap["failures"] > 0 and fails["ips"] > 1)
        reasons = [f"{fails['failures']} échecs en 24 h depuis {fails['ips']} IP, puis connexion réussie depuis "
                   f"{', '.join(success_ips[:3]) or '?'}"]

        if from_attackers and not usual:
            reasons.append("La connexion réussie vient d'une IP qui participait à l'attaque : compte compromis")
            return Qualification("attack", reasons, CRITICAL)
        if usual and fails["ips"] <= 1:
            reasons.append("Échecs et succès depuis l'IP habituelle : erreur de saisie de l'utilisateur")
            return Qualification("benign", reasons, LOW)
        if usual:
            reasons.append("Compte attaqué, mais la connexion vient de l'IP habituelle de l'utilisateur")
            reasons.append("Changer le mot de passe par précaution et vérifier le MFA")
            return Qualification("suspicious", reasons, MEDIUM)
        reasons.append("Connexion depuis une IP jamais vue pour ce compte : confirmer auprès de l'utilisateur")
        return Qualification("suspicious", reasons, HIGH)


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


# Opérateurs d'hébergement, de cloud ou d'anonymisation : un agent s'y connecte rarement au VPN
HOSTING_HINTS = (
    "hosting", "host", "cloud", "datacenter", "data center", "server", "vps", "ovh", "hetzner", "digitalocean",
    "linode", "akamai", "vultr", "contabo", "scaleway", "online s.a.s", "amazon", "aws", "google", "microsoft",
    "azure", "alibaba", "tencent", "oracle", "leaseweb", "m247", "choopa", "frantech", "buyvm", "colocrossing",
    "tor", "freiheit", "privacy", "vpn", "proxy",
)


def is_hosting(asn: str) -> bool:
    text = asn.lower()
    return any(re.search(r"\b" + re.escape(hint), text) for hint in HOSTING_HINTS)


def _is_internal(ip: str) -> bool:
    """Réseaux privés RFC 1918 / ULA uniquement (`is_private` inclut aussi les plages de documentation)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL if net.version == addr.version)
