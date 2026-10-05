"""Leurres (« honeytokens ») : éléments qu'aucun usage légitime ne touche ; toute activité est donc malveillante.

- **Compte leurre** : compte AD jamais utilisé (ex. « adm-sauvegarde » avec un faux mot de passe en description, et un
  SPN pour piéger le « kerberoasting ») : toute tentative de connexion, de ticket ou de modification alerte.
- **Dossier ou fichier leurre** : « \\\\SRV-FICHIERS\\Paie_2026 », « Mots de passe.xlsx » (audit des accès requis).
- **Machine leurre** : adresse ou nom d'une machine sans usage : toute connexion vers elle alerte.
- **Chaîne leurre** : faux mot de passe ou fausse clé d'API laissés en évidence ; leur apparition dans un journal
  (connexion, ligne de commande) prouve qu'ils ont été trouvés et essayés.

Réglages : Paramètres › Détection. Alerte UC-45, critique, jamais regroupée.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from minisoc.accounts import normalize as normalize_account
from minisoc.ecs import Event


@dataclass
class Decoys:
    accounts: set[str] = field(default_factory=set)
    paths: list[str] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    tokens: list[str] = field(default_factory=list)

    @classmethod
    def from_cfg(cls, cfg: dict) -> Decoys:
        def items(key: str) -> list[str]:
            return [str(v).strip() for v in cfg.get(key) or [] if str(v).strip()]

        return cls(
            accounts={normalize_account(a) for a in items("decoy_accounts")},
            paths=[p.lower().strip("\\/") for p in items("decoy_paths") if len(p.strip("\\/")) >= 3],
            hosts={h.lower().split(".")[0] if not h.replace(".", "").isdigit() else h for h in items("decoy_hosts")},
            tokens=[t for t in items("decoy_tokens") if len(t) >= 8],  # assez long pour ne pas apparaître par hasard
        )

    @property
    def active(self) -> bool:
        return bool(self.accounts or self.paths or self.hosts or self.tokens)

    def match(self, ev: Event) -> tuple[str, str] | None:
        """(type, valeur) du leurre touché, ou None."""
        if not self.active:
            return None
        if self.accounts:
            user = normalize_account(ev.user_name)
            if user and user in self.accounts:
                return "compte", user
            # Modification d'un compte leurre par un autre (le compte visé est parfois dans le message)
            text = ev.message.lower()
            for account in self.accounts:
                if account and f"{account} " in f"{text} " and ev.module == "windows" and ev.category == "iam":
                    return "compte", account
        if self.paths:
            haystack = f"{ev.file_path}\n{ev.message}".lower()
            for path in self.paths:
                if path in haystack:
                    return "dossier", path
        if self.hosts:
            for value in (ev.destination_ip, ev.host_ip):
                if value and value in self.hosts:
                    return "machine", value
            host = ev.host_name.lower().split(".")[0]
            if host and host in self.hosts and ev.module != "harfanglab":  # l'EDR de la machine leurre : bruit
                return "machine", host
        if self.tokens:
            haystack = f"{ev.message}\n{ev.raw}"
            for token in self.tokens:
                if token in haystack:
                    return "chaîne", token[:4] + "…"  # la valeur complète n'est pas recopiée dans l'alerte
        return None
