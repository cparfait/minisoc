"""Pseudonymisation des données envoyées à un fournisseur d'IA externe (RGPD : minimisation).

Comptes, postes, adresses e-mail et IP internes sont remplacés par des jetons stables dans une requête
(USER_1, HOST_2, IP_INT_3, EMAIL_1). La correspondance reste sur le serveur et sert à remettre les vraies
valeurs dans la réponse affichée. Les IP publiques (attaquants) sont conservées : elles sont utiles à
l'analyse et ne désignent pas les agents.
"""

from __future__ import annotations

import ipaddress
import re

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TOKEN = re.compile(r"\b(?:USER|HOST|EMAIL|IP_INT)_\d+\b")
_PARTIAL_TAIL = re.compile(r"(?:U|US|USE|USER|USER_|H|HO|HOS|HOST|HOST_|E|EM|EMA|EMAI|EMAIL|EMAIL_|I|IP|IP_|IP_I|"
                           r"IP_IN|IP_INT|IP_INT_|(?:USER|HOST|EMAIL|IP_INT)_\d*)$")


class Pseudonymizer:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
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
            addr = ipaddress.ip_address(value)
        except ValueError:
            return value
        internal = addr.is_private and not _is_documentation(addr)
        return self._token("IP_INT", value) if internal else value

    def text(self, value: str) -> str:
        """Texte libre (messages de journaux) : e-mails, IP internes et valeurs déjà connues remplacés."""
        if not self.enabled or not value:
            return value
        value = _EMAIL.sub(lambda m: self._token("EMAIL", m.group(0)), value)
        value = _IPV4.sub(lambda m: self.ip(m.group(0)), value)
        for key, token in sorted(self.forward.items(), key=lambda kv: -len(kv[0])):
            kind, _, original = key.partition(":")
            if kind in ("USER", "HOST") and len(original) >= 3:
                value = re.sub(re.escape(original), token, value, flags=re.IGNORECASE)
        return value

    def restore(self, text: str) -> str:
        if not self.reverse:
            return text
        return _TOKEN.sub(lambda m: self.reverse.get(m.group(0), m.group(0)), text)


def _is_documentation(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # Plages de documentation (RFC 5737) : traitées comme publiques, pour les tests de recette
    return any(addr in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


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
