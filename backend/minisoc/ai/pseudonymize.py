"""Pseudonymisation des données envoyées à un fournisseur d'IA externe (RGPD : minimisation, sécurité).

Comptes, postes, adresses e-mail, IP internes (v4 et v6), IP publiques de la collectivité, domaines internes
(DNS, NetBIOS, DN LDAP), noms d'objets de l'annuaire, SID de domaine et adresses MAC sont remplacés par des
jetons stables dans une requête (USER_1, HOST_2, IP_INT_3, IP_ORG_1, DOMAIN_1, NAME_1, SID_1, MAC_1, EMAIL_1).
La correspondance reste sur le serveur et sert à remettre les vraies valeurs dans la réponse affichée. Les IP
publiques des attaquants sont conservées : elles sont utiles à l'analyse et ne désignent pas les agents.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

KINDS = ("USER", "HOST", "EMAIL", "IP_INT", "IP_ORG", "DOMAIN", "NAME", "SID", "MAC")

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Candidat IPv6 (validé ensuite par ipaddress : une heure « 12:30:45 » n'en est pas une)
_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}(?:[0-9a-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})(?:%[\w.]+)?(?![\w:])",
                   re.IGNORECASE)
_MAC = re.compile(r"(?<![\w:.-])(?:(?:[0-9a-f]{2}([:-]))(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}|"
                  r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})(?![\w:.-])", re.IGNORECASE)
_SID = re.compile(r"\bS-1-5-21-(\d+-\d+-\d+)(?=-\d+\b|\b)")
# Profils : C:\Users\jdupont, \\pc\c$\Users\jdupont (barres doublées dans du JSON), /home/jdupont, /Users/jdupont
_HOME_WIN = re.compile(r"((?:\\{1,2})(?:users|documents and settings)\\{1,2})([^\\/\s\"':;,|<>*?]+)", re.IGNORECASE)
_HOME_UNIX = re.compile(r"(/(?:home|Users)/)([^/\s\"':;,|<>*?]+)")
_PROFILES = {"public", "default", "default user", "all users", "defaultapppool"}
# DOMAINE\compte : nom NetBIOS en majuscules (forme des journaux Windows) ou domaine interne connu
_DOMAIN_ACCOUNT = re.compile(r"(?<![\w\\/:.$%-])([A-Za-z][\w-]{1,14})(\\{1,2})([\w.-]+\$?)(?![\w\\$])")
_NOT_DOMAINS = {"hklm", "hkcu", "hkcr", "hku", "hkcc", "authority", "builtin", "service", "manager", "host",
                "apppool", "machine", "workgroup", "system32", "windows", "device", "registry", "global", "local",
                "session", "sessions", "basenamedobjects"}
# DN LDAP : la valeur d'un CN (personne, poste, groupe) et les composants DC (domaine)
_DN_CN = re.compile(r"\b(CN=)((?:\\,|[^,=;\"\n\r<>])+?)(?=\s*(?:,|;|\"|$|\n|\r|<|>))", re.IGNORECASE | re.MULTILINE)
_DN_DC = re.compile(r"\bDC=([\w-]+)((?:\s*,\s*DC=[\w-]+)*)", re.IGNORECASE)
_KEEP_CN = {"users", "computers", "builtin", "system", "configuration", "schema", "policies", "program data",
            "microsoft", "domain admins", "admins du domaine", "enterprise admins", "administrateurs de l'entreprise",
            "schema admins", "administrateurs du schéma", "administrators", "administrateurs", "domain users",
            "utilisateurs du domaine", "domain computers", "ordinateurs du domaine", "domain controllers",
            "contrôleurs de domaine", "account operators", "opérateurs de compte", "backup operators",
            "opérateurs de sauvegarde", "server operators", "opérateurs de serveur", "protected users",
            "group policy creator owners", "dnsadmins", "key admins", "enterprise key admins", "krbtgt"}
# Noms DNS : suffixes internes reconnus sans configuration
_FQDN = re.compile(r"(?<![\w@.-])[a-z0-9_][a-z0-9_-]{0,62}(?:\.[a-z0-9_-]{1,63})+(?![\w-]|\.[a-z0-9])", re.IGNORECASE)
_INTERNAL_TLDS = ("local", "lan", "intra", "intranet", "internal", "corp", "localdomain", "home.arpa")

_TOKEN = re.compile(r"\b(?:" + "|".join(KINDS) + r")_\d+\b")


def _partial_tail() -> re.Pattern[str]:
    """Fin de fragment qui peut être le début d'un jeton (« HO », « DOMAIN_ », « SID_1 ») : à garder en attente."""
    prefixes = {(kind + "_")[:i] for kind in KINDS for i in range(1, len(kind) + 2)}
    alternatives = sorted(prefixes, key=len, reverse=True)
    return re.compile(r"(?:(?:" + "|".join(KINDS) + r")_\d*|" + "|".join(map(re.escape, alternatives)) + r")$")


_PARTIAL_TAIL = _partial_tail()


def _items(value) -> list[str]:
    items = value if isinstance(value, list) else str(value or "").replace(";", ",").split(",")
    return [str(i).strip() for i in items if str(i).strip()]


def internal_domains(cfg: dict) -> list[str]:
    """Domaines internes : paramètre dédié, base de l'annuaire (DC=mairie,DC=local) et serveur LDAP."""
    domains = [d.lower().strip(".") for d in _items(cfg.get("ai_internal_domains"))]
    dcs = re.findall(r"DC=([\w-]+)", str(cfg.get("ldap_base_dn") or ""), re.IGNORECASE)
    if len(dcs) >= 2:
        domains.append(".".join(dcs).lower())
    host = re.sub(r"^\w+://", "", str(cfg.get("ldap_url") or "")).split("/")[0].split(":")[0].lower()
    if host.count(".") >= 2 and not _IPV4.fullmatch(host):
        domains.append(host.split(".", 1)[1])
    return sorted(set(domains), key=len, reverse=True)


def for_settings(cfg: dict, enabled: bool) -> Pseudonymizer:
    networks = []
    for net in _items(cfg.get("ai_org_networks")):
        try:
            networks.append(ipaddress.ip_network(net, strict=False))
        except ValueError:
            continue
    return Pseudonymizer(enabled=enabled, org_networks=networks, domains=internal_domains(cfg))


class Pseudonymizer:
    def __init__(self, enabled: bool = True, org_networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network] = (),
                 domains: Iterable[str] = ()) -> None:
        self.enabled = enabled
        self.org_networks = list(org_networks)
        self.domains = sorted({d.lower().strip(".") for d in domains if d.strip(".")}, key=len, reverse=True)
        self.forward: dict[str, str] = {}
        self.reverse: dict[str, str] = {}
        self.counters: dict[str, int] = {}

    def _token(self, kind: str, value: str) -> str:
        key = f"{kind}:{value.lower()}"
        if key not in self.forward:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            token = f"{kind}_{self.counters[kind]}"
            self.forward[key] = token
            self.reverse[token] = value
        return self.forward[key]

    def user(self, value: str) -> str:
        return self._token("USER", value) if self.enabled and value else value

    def host(self, value: str) -> str:
        return self._token("HOST", value) if self.enabled and value else value

    def ip(self, value: str) -> str:
        if not self.enabled or not value:
            return value
        try:
            addr = ipaddress.ip_address(value.split("%")[0])
        except ValueError:
            return value
        if any(addr.version == net.version and addr in net for net in self.org_networks):
            return self._token("IP_ORG", value)
        internal = (addr.is_private or addr.is_link_local) and not _is_documentation(addr)
        return self._token("IP_INT", value) if internal else value

    def domain(self, label: str) -> str:
        """Partie propre à la collectivité d'un domaine (« mairie » dans mairie.local, MAIRIE en NetBIOS)."""
        return self._token("DOMAIN", label.lower()) if self.enabled and label else label

    def text(self, value: str) -> str:
        """Texte libre (messages de journaux, questions) : toutes les valeurs identifiantes remplacées."""
        if not self.enabled or not value:
            return value
        value = _EMAIL.sub(lambda m: self._token("EMAIL", m.group(0)), value)
        value = _HOME_WIN.sub(self._home, value)
        value = _HOME_UNIX.sub(self._home, value)
        value = _DN_CN.sub(self._dn_cn, value)
        value = _DN_DC.sub(self._dn_dc, value)
        value = _SID.sub(lambda m: m.group(0).replace(m.group(1), self._token("SID", m.group(1))), value)
        value = _MAC.sub(self._mac, value)
        value = _IPV4.sub(lambda m: self.ip(m.group(0)), value)
        value = _IPV6.sub(self._ipv6, value)
        value = _FQDN.sub(self._fqdn, value)
        value = _DOMAIN_ACCOUNT.sub(self._domain_account, value)
        for key, token in sorted(self.forward.items(), key=lambda kv: -len(kv[0])):
            kind, _, original = key.partition(":")
            if kind in ("USER", "HOST") and len(original) >= 3:
                value = re.sub(rf"(?<!\w){re.escape(original)}(?!\w)", token, value, flags=re.IGNORECASE)
        return value

    def _home(self, m: re.Match[str]) -> str:
        name = m.group(2)
        if name.lower() in _PROFILES or _TOKEN.fullmatch(name):
            return m.group(0)
        return m.group(1) + self._token("USER", name)

    def _dn_cn(self, m: re.Match[str]) -> str:
        name = m.group(2).strip()
        if name.lower() in _KEEP_CN or _TOKEN.fullmatch(name):
            return m.group(0)
        known = self.forward.get(f"USER:{name.lower()}") or self.forward.get(f"HOST:{name.lower()}")
        return m.group(1) + (known or self._token("NAME", name.replace("\\,", ",")))

    def _dn_dc(self, m: re.Match[str]) -> str:
        labels = re.findall(r"DC=([\w-]+)", m.group(0), re.IGNORECASE)
        if len(labels) == 1:
            return f"DC={self.domain(labels[0])}"
        return f"DC={self.domain('.'.join(labels[:-1]))},DC={labels[-1]}"

    def _mac(self, m: re.Match[str]) -> str:
        digits = re.sub(r"[^0-9a-f]", "", m.group(0).lower())
        return m.group(0) if digits in ("000000000000", "ffffffffffff") else self._token("MAC", m.group(0))

    def _ipv6(self, m: re.Match[str]) -> str:
        candidate = m.group(0)
        try:
            ipaddress.ip_address(candidate.split("%")[0])
        except ValueError:
            return candidate
        return self.ip(candidate)

    def _fqdn(self, m: re.Match[str]) -> str:
        name = m.group(0)
        lower = name.lower()
        suffix = next((d for d in self.domains if lower == d or lower.endswith("." + d)), "")
        if not suffix:
            tld = next((t for t in _INTERNAL_TLDS if lower.endswith("." + t)), "")
            if not tld:
                return name
            labels = lower[: -len(tld) - 1].split(".")
            if len(labels) == 1:  # pc-compta.local : un nom de poste, pas un domaine
                return f"{self.host(name.split('.')[0])}.{name[-len(tld):]}"
            suffix = f"{labels[-1]}.{tld}"
        prefix = name[: len(name) - len(suffix)].rstrip(".")
        org, _, top = suffix.rpartition(".") if "." in suffix else (suffix, "", "")
        if suffix.endswith(".home.arpa"):
            org, top = suffix[: -len(".home.arpa")], "home.arpa"
        out = self.domain(org) + (f".{top}" if top else "")
        if prefix:
            first, _, rest = prefix.partition(".")
            out = ".".join(p for p in (self.host(first), rest, out) if p)
        return out

    def _domain_account(self, m: re.Match[str]) -> str:
        domain, sep, account = m.groups()
        known = domain.lower() in {d.split(".")[0] for d in self.domains} or f"DOMAIN:{domain.lower()}" in self.forward
        if domain.lower() in _NOT_DOMAINS or not (domain.isupper() or known) or _TOKEN.fullmatch(account):
            return m.group(0)
        name = self.host(account[:-1]) + "$" if account.endswith("$") else self.user(account)
        return f"{self.domain(domain)}{sep}{name}"

    def restore(self, text: str) -> str:
        if not self.reverse:
            return text
        return _TOKEN.sub(lambda m: self.reverse.get(m.group(0), m.group(0)), text)


def _is_documentation(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # Plages de documentation (RFC 5737, RFC 3849) : traitées comme publiques, pour les tests de recette
    nets = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
    return any(addr.version == n.version and addr in n for n in map(ipaddress.ip_network, nets))


class StreamRestorer:
    """Remet les vraies valeurs dans un flux de texte, sans couper un jeton réparti sur deux fragments."""

    def __init__(self, pseudo: Pseudonymizer) -> None:
        self.pseudo = pseudo
        self.buffer = ""

    def feed(self, chunk: str) -> str:
        self.buffer += chunk
        match = _PARTIAL_TAIL.search(self.buffer)
        cut = match.start() if match else len(self.buffer)
        ready, self.buffer = self.buffer[:cut], self.buffer[cut:]
        return self.pseudo.restore(ready)

    def flush(self) -> str:
        ready, self.buffer = self.buffer, ""
        return self.pseudo.restore(ready)
