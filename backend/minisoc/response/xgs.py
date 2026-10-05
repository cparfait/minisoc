"""Client de l'API XML du Sophos Firewall (SFOS / XGS) : ajout et retrait d'IP dans un groupe d'hôtes bloqués.

Prérequis côté pare-feu (une seule fois) :
  1. Administration > Paramètres d'administration > API : activer l'API, n'autoriser QUE l'adresse du Mini-SOC.
  2. Compte d'administration dédié, profil limité aux objets hôtes (pas d'administrateur complet).
  3. Créer le groupe d'hôtes IP « MiniSOC-Blocages » (vide).
  4. Règle de pare-feu en tête : source = ce groupe → Abandonner (trafic traversant).
  5. Le VPN et le portail étant hébergés par le pare-feu lui-même, ajouter aussi une exception ACL de service
     local (Administration > Accès à l'appareil) : source = ce groupe, services VPN SSL / IPsec / portail →
     Abandonner. Sans elle, une IP « bloquée » peut continuer à attaquer le VPN.
Le jeu exact de libellés dépend de la version de SFOS ; le bouton « Tester » vérifie l'accès et le groupe.
"""

from __future__ import annotations

import ipaddress
import ssl
from xml.etree.ElementTree import Element, ParseError
from xml.sax.saxutils import escape

import httpx
from defusedxml.ElementTree import fromstring

HOST_PREFIX = "MSOC_"


class XGSError(RuntimeError):
    pass


def host_name(ip: str) -> str:
    """Nom d'objet stable et court : MSOC_203.0.113.12 (IPv6 : « : » remplacés)."""
    return HOST_PREFIX + ip.replace(":", "-")


class XGSClient:
    def __init__(self, cfg: dict) -> None:
        if not cfg.get("xgs_url") or not cfg.get("xgs_user") or not cfg.get("xgs_password"):
            raise XGSError("Pare-feu non configuré (Paramètres > Réponse)")
        self.url = cfg["xgs_url"].rstrip("/") + "/webconsole/APIController"
        self.user = cfg["xgs_user"]
        self.password = cfg["xgs_password"]
        self.group = cfg.get("xgs_block_group") or "MiniSOC-Blocages"
        if cfg.get("xgs_verify_tls", True):
            self.verify: ssl.SSLContext | bool = ssl.create_default_context(cadata=cfg.get("xgs_ca_cert") or None)
        else:
            self.verify = False

    def _envelope(self, body: str) -> str:
        return (f"<Request><Login><Username>{escape(self.user)}</Username>"
                f"<Password passwordform=\"plain\">{escape(self.password)}</Password></Login>{body}</Request>")

    async def _call(self, body: str) -> Element:
        try:
            async with httpx.AsyncClient(timeout=20, verify=self.verify) as client:
                # POST de formulaire : le mot de passe ne figure pas dans l'URL (ni dans les journaux d'accès)
                response = await client.post(self.url, data={"reqxml": self._envelope(body)})
        except httpx.HTTPError as exc:
            raise XGSError(
                f"Pare-feu injoignable ({type(exc).__name__}) : vérifier l'adresse et le port 4444"
            ) from None
        if response.status_code >= 400:
            raise XGSError(f"Pare-feu : HTTP {response.status_code}")
        try:
            root = fromstring(response.text)  # defusedxml : protège contre les entités XML malveillantes
        except ParseError:
            raise XGSError("Réponse illisible du pare-feu") from None
        login = root.find("Login/status")
        if login is not None and "success" not in (login.text or "").lower():
            raise XGSError("Connexion à l'API refusée : identifiants, droits, ou IP du Mini-SOC non autorisée")
        status = root.find(".//Status")
        if status is not None and status.get("code") not in (None, "200", "216"):
            raise XGSError(f"Pare-feu : {(status.text or '').strip()} (code {status.get('code')})")
        return root

    async def test(self) -> str:
        root = await self._call(f"<Get><IPHostGroup><Name>{escape(self.group)}</Name></IPHostGroup></Get>")
        if root.find(".//IPHostGroup") is None:
            raise XGSError(f"Connexion réussie, mais le groupe d'hôtes « {self.group} » est introuvable : le créer")
        return f"Connexion réussie, groupe « {self.group} » présent"

    async def get(self, entity: str) -> list[Element]:
        """Lecture seule : tous les objets d'un type (ex. FirewallRule, IPHostGroup)."""
        if not entity.isalnum():
            raise XGSError("type d'objet invalide")
        root = await self._call(f"<Get><{entity}></{entity}></Get>")
        return [e for e in root.iter(entity) if len(e)]

    async def firewall_rules(self) -> list[dict]:
        """Résumé des règles de pare-feu, dans l'ordre du XGS."""
        return [summarize_rule(e) for e in await self.get("FirewallRule")]

    async def block(self, ip: str) -> None:
        addr = ipaddress.ip_address(ip)
        family = "IPv4" if addr.version == 4 else "IPv6"
        body = (f"<Set operation=\"add\"><IPHost><Name>{escape(host_name(ip))}</Name><IPFamily>{family}</IPFamily>"
                f"<HostType>IP</HostType><IPAddress>{escape(str(addr))}</IPAddress>"
                f"<HostGroupList><HostGroup>{escape(self.group)}</HostGroup></HostGroupList></IPHost></Set>")
        await self._call(body)

    async def unblock(self, ip: str) -> None:
        await self._call(f"<Remove><IPHost><Name>{escape(host_name(ip))}</Name></IPHost></Remove>")


def _texts(node: Element | None, path: str) -> list[str]:
    return [(e.text or "").strip() for e in node.iterfind(path)] if node is not None else []


def summarize_rule(rule: Element) -> dict:
    """Champs utiles d'une règle (SFOS 18 à 21 : règles « réseau » et « utilisateur »)."""
    policy = rule.find("NetworkPolicy")
    if policy is None:
        policy = rule.find("UserPolicy")
    return {
        "name": (rule.findtext("Name") or "").strip(),
        "position": (rule.findtext("Position") or "").strip(),
        "status": (rule.findtext("Status") or "").strip(),
        "type": (rule.findtext("PolicyType") or "").strip(),
        "description": (rule.findtext("Description") or "").strip()[:200],
        "action": (policy.findtext("Action") if policy is not None else "") or "",
        "log": (policy.findtext("LogTraffic") if policy is not None else "") or "",
        "source_zones": _texts(policy, "SourceZones/Zone"),
        "destination_zones": _texts(policy, "DestinationZones/Zone"),
        "sources": _texts(policy, "SourceNetworks/Network"),
        "destinations": _texts(policy, "DestinationNetworks/Network"),
        "services": _texts(policy, "Services/Service"),
    }
