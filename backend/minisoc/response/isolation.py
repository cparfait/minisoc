"""Isolation réseau d'un poste par l'EDR (F-27) : HarfangLab ou Bitdefender GravityZone.

Le poste isolé ne communique plus qu'avec la console de l'EDR (l'analyse et la levée d'isolation restent possibles).
Garde-fous : désactivé par défaut ; jetons d'API distincts des jetons de lecture (droit d'isolation uniquement) ;
confirmation par la saisie du nom du poste ; traçabilité (journal d'audit, historique de l'alerte, chronologie de
l'incident). Les identifiants d'agent sont lus dans le journal brut des alertes de l'EDR, jamais saisis à la main.

API utilisées :
  HarfangLab  POST /api/data/endpoint/Agent/isolate/    {"agent_ids": [...]}  (deisolate/ pour lever)
              GET  /api/data/endpoint/Agent/<id>/        (état : isolation_state)
  Bitdefender JSON-RPC /v1.0/jsonrpc/incidents  createIsolateEndpointTask / createRestoreEndpointFromIsolationTask
"""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass

import httpx

from minisoc.connectors import gravityzone
from minisoc.parsers.common import first

EDRS = ("harfanglab", "bitdefender")


class IsolationError(RuntimeError):
    pass


@dataclass
class Target:
    edr: str
    agent_id: str
    host: str

    def as_dict(self) -> dict:
        return {"edr": self.edr, "agent_id": self.agent_id, "host": self.host}


def targets_from_events(events: list[dict]) -> list[Target]:
    """Postes isolables d'après les événements d'une alerte (modules harfanglab et bitdefender)."""
    found: dict[tuple[str, str], Target] = {}
    for event in events:
        module = event.get("module")
        if module not in EDRS:
            continue
        try:
            raw = json.loads(event.get("raw") or "{}")
        except ValueError:
            continue
        if module == "harfanglab":
            agent_id = first(raw, "agent.agentid", "agent_id", "agent.id")
            host = first(raw, "agent.hostname", "hostname", default=event.get("host_name") or "")
        else:
            agent_id = first(raw, "computer_id", "endpointId", "endpoint_id", "computerId")
            host = first(raw, "computer_name", "endpoint_name", "computerName", default=event.get("host_name") or "")
        if agent_id:
            found[(module, agent_id)] = Target(module, agent_id, host)
    return list(found.values())


def configured(cfg: dict, edr: str) -> bool:
    if edr == "harfanglab":
        return bool(cfg.get("harfanglab_url") and cfg.get("harfanglab_isolation_token"))
    return bool(cfg.get("bitdefender_api_url") and cfg.get("bitdefender_api_key"))


async def isolate(cfg: dict, target: Target, release: bool = False) -> str:
    """Demande l'isolation (ou sa levée) ; renvoie un message lisible. Lève IsolationError en cas de refus."""
    if not cfg.get("isolation_enabled"):
        raise IsolationError("Isolation de poste désactivée (Intégrations › Isolation de poste)")
    if not configured(cfg, target.edr):
        raise IsolationError(f"Accès d'isolation {target.edr} non configuré")
    if target.edr == "harfanglab":
        return await _harfanglab(cfg, target, release)
    return await _bitdefender(cfg, target, release)


async def _harfanglab(cfg: dict, target: Target, release: bool) -> str:
    action = "deisolate" if release else "isolate"
    async with httpx.AsyncClient(base_url=cfg["harfanglab_url"].rstrip("/"), timeout=30,
                                 verify=bool(cfg.get("harfanglab_verify_tls", True)),
                                 headers={"Authorization": f"Token {cfg['harfanglab_isolation_token']}"}) as client:
        response = await client.post(f"/api/data/endpoint/Agent/{action}/", json={"agent_ids": [target.agent_id]})
    if response.status_code in (401, 403):
        raise IsolationError("HarfangLab : jeton d'isolation refusé ou sans le droit d'isoler")
    if response.status_code >= 400:
        raise IsolationError(f"HarfangLab : HTTP {response.status_code} : {response.text[:200]}")
    data = response.json() if response.content else {}
    if target.agent_id in (data.get("policy_not_allowed") or []):
        raise IsolationError("HarfangLab : la politique de ce poste n'autorise pas l'isolation")
    verb = "Levée d'isolation demandée" if release else "Isolation demandée"
    return f"{verb} à HarfangLab pour {target.host} (appliquée au prochain contact de l'agent, sous une minute)"


async def _bitdefender(cfg: dict, target: Target, release: bool) -> str:
    method = "createRestoreEndpointFromIsolationTask" if release else "createIsolateEndpointTask"
    token = base64.b64encode(f"{cfg['bitdefender_api_key']}:".encode()).decode()
    payload = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": {"endpointId": target.agent_id}}
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(gravityzone.api_url(cfg) + "/v1.0/jsonrpc/incidents", json=payload,
                                     headers={"Authorization": f"Basic {token}"})
    if response.status_code in (401, 403):
        raise IsolationError("Bitdefender : clé d'API refusée ou sans le droit « Incidents »")
    if response.status_code >= 400:
        raise IsolationError(f"Bitdefender : HTTP {response.status_code} : {response.text[:200]}")
    data = response.json()
    if data.get("error"):
        raise IsolationError(f"Bitdefender : {str(data['error'].get('message') or data['error'])[:200]}")
    verb = "Levée d'isolation demandée" if release else "Isolation demandée"
    return f"{verb} à GravityZone pour {target.host} (tâche créée)"


async def test(cfg: dict) -> tuple[bool, str]:
    """Lecture seule : vérifie que chaque accès configuré répond (aucune isolation)."""
    results = []
    if configured(cfg, "harfanglab"):
        async with httpx.AsyncClient(base_url=cfg["harfanglab_url"].rstrip("/"), timeout=20,
                                     verify=bool(cfg.get("harfanglab_verify_tls", True)),
                                     headers={"Authorization": f"Token {cfg['harfanglab_isolation_token']}"}) as c:
            try:
                r = await c.get("/api/data/endpoint/Agent/", params={"limit": 1})
                results.append((r.status_code == 200, f"HarfangLab : HTTP {r.status_code}"))
            except httpx.HTTPError as exc:
                results.append((False, f"HarfangLab injoignable ({type(exc).__name__})"))
    if configured(cfg, "bitdefender"):
        token = base64.b64encode(f"{cfg['bitdefender_api_key']}:".encode()).decode()
        payload = {"jsonrpc": "2.0", "id": "1", "method": "getEndpointsList", "params": {"perPage": 1}}
        async with httpx.AsyncClient(timeout=20) as c:
            try:
                r = await c.post(gravityzone.api_url(cfg) + "/v1.0/jsonrpc/network", json=payload,
                                 headers={"Authorization": f"Basic {token}"})
                ok = r.status_code == 200 and not r.json().get("error")
                results.append((ok, f"Bitdefender : HTTP {r.status_code}"))
            except (httpx.HTTPError, ValueError) as exc:
                results.append((False, f"Bitdefender injoignable ({type(exc).__name__})"))
    if not results:
        return False, "Aucun accès d'isolation configuré (jeton HarfangLab ou clé Bitdefender)"
    return all(ok for ok, _ in results), " ; ".join(text for _, text in results)
