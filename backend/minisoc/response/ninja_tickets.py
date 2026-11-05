"""Tickets NinjaOne : ouverture depuis une alerte et suivi de leur état.

Seule écriture vers NinjaOne, à la demande d'un analyste. Garde-fous, comme pour l'isolation de poste : désactivé par
défaut ; application NinjaOne dédiée, distincte de l'application de lecture en portée Surveillance ; texte relu avant
l'envoi, sans journaux bruts ; traçabilité (journal d'audit, historique de l'alerte, chronologie de l'incident).
Le ticket ne clôture jamais l'alerte : résoudre un ticket ne prouve pas que la menace est traitée.

API publique v2 :
  POST /v2/ticketing/ticket          création (organisation, formulaire, sujet, description, appareil facultatif)
  GET  /v2/ticketing/ticket/{id}     état (status : name, displayName)
  GET  /v2/ticketing/ticket-form     formulaires, GET /v2/organizations : organisations (bouton « Tester »)
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import httpx
import redis.asyncio as aioredis

from minisoc.connectors.ninjaone import POSTURE_KEY, host

SCOPE = "monitoring management"
TIMEOUT = 30
CLOSED = {"CLOSED"}  # un ticket « résolu » peut encore être rouvert : il reste suivi
MISSING = "MISSING"


class TicketError(RuntimeError):
    pass


def has_credentials(cfg: dict) -> bool:
    return bool(cfg.get("ninjaone_tickets_client_id") and cfg.get("ninjaone_tickets_client_secret"))


def configured(cfg: dict) -> bool:
    return has_credentials(cfg) and bool(cfg.get("ninjaone_tickets_org_id") and cfg.get("ninjaone_tickets_form_id"))


def enabled(cfg: dict) -> bool:
    return bool(cfg.get("ninjaone_tickets_enabled")) and configured(cfg)


def console_url(cfg: dict, ticket_id) -> str:
    return f"https://{host(cfg)}/#/ticketing/ticket/{int(ticket_id)}"


class TicketClient:
    def __init__(self, cfg: dict, client: httpx.AsyncClient) -> None:
        self.cfg = cfg
        self.client = client
        self.base = f"https://{host(cfg)}"
        self._token: tuple[str, float] | None = None

    async def token(self) -> str:
        if self._token and self._token[1] > time.monotonic() + 60:
            return self._token[0]
        response = await self.client.post(
            f"{self.base}/ws/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.cfg["ninjaone_tickets_client_id"],
                "client_secret": self.cfg["ninjaone_tickets_client_secret"],
                "scope": SCOPE,
            },
        )
        if response.status_code in (400, 401, 403):
            raise TicketError("identifiants NinjaOne refusés (identifiant, secret, ou portées Surveillance et Gestion)")
        response.raise_for_status()
        data = response.json()
        self._token = (data["access_token"], time.monotonic() + float(data.get("expires_in", 3600)))
        return self._token[0]

    async def request(self, method: str, path: str, **kwargs) -> httpx.Response:
        headers = {"Authorization": f"Bearer {await self.token()}"}
        response = await self.client.request(method, f"{self.base}{path}", headers=headers, **kwargs)
        if response.status_code in (401, 403):
            raise TicketError("accès refusé par NinjaOne (portée Gestion, droits de l'application, module Ticketing ?)")
        return response

    async def create(self, subject: str, body: str, node_id: int | None = None) -> dict:
        ticket = {
            "clientId": int(self.cfg["ninjaone_tickets_org_id"]),
            "ticketFormId": int(self.cfg["ninjaone_tickets_form_id"]),
            "subject": subject,
            "description": {"public": False, "body": body},
        }
        if node_id:
            ticket["nodeId"] = node_id
        response = await self.request("POST", "/v2/ticketing/ticket", json=ticket)
        if response.status_code >= 400:
            raise TicketError(f"NinjaOne refuse le ticket : HTTP {response.status_code} : {response.text[:300]}")
        data = response.json()
        if not isinstance(data, dict) or not data.get("id"):
            raise TicketError("réponse de NinjaOne sans numéro de ticket : vérifier dans la console avant de réessayer")
        return data

    async def read(self, ticket_id: int) -> dict | None:
        """État du ticket ; None s'il n'existe plus dans NinjaOne."""
        response = await self.request("GET", f"/v2/ticketing/ticket/{int(ticket_id)}")
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise TicketError(f"lecture du ticket {ticket_id} : HTTP {response.status_code}")
        return response.json()


def state_of(data: dict) -> dict:
    """État lisible d'un ticket lu dans NinjaOne."""
    status = data.get("status")
    if not isinstance(status, dict):
        status = {"name": status}
    name = str(status.get("name") or "").upper()
    return {"status": name, "label": str(status.get("displayName") or status.get("name") or "état inconnu")}


def is_followed(ticket: dict | None) -> bool:
    return bool(ticket and ticket.get("id") and ticket.get("status") not in CLOSED and ticket.get("status") != MISSING)


def updated(ticket: dict, data: dict | None, now: str | None = None) -> tuple[dict, str]:
    """Ticket mis à jour d'après NinjaOne, et phrase pour l'historique de l'alerte si son état a changé."""
    now = now or datetime.now(timezone.utc).isoformat()
    state = {"status": MISSING, "label": "introuvable dans NinjaOne"} if data is None else state_of(data)
    fresh = {**ticket, **state, "checked_at": now}
    changed = state["status"] != ticket.get("status")
    return fresh, f"Ticket NinjaOne n° {ticket['id']} : {state['label']}." if changed else ""


def _when(value: str | None) -> str:
    return f"{value[:16].replace('T', ' ')} UTC" if value else "?"


def draft(alert: dict) -> dict:
    """Texte proposé à l'analyste, relu avant l'envoi : l'essentiel de l'alerte, sans journaux bruts."""
    details = alert.get("details") or {}
    qualification = details.get("qualification") or {}
    hosts = [h["name"] for h in alert.get("hosts") or []]
    lines = [
        f"Alerte Mini-SOC n° {alert['id']} : {alert['title']}",
        f"Sévérité : {alert.get('severity') or '?'}",
        f"Règle : {alert.get('rule_id')} – {alert.get('rule_name')}",
        f"Occurrences : {alert.get('count')} (du {_when(alert.get('first_seen'))} au {_when(alert.get('last_seen'))})",
    ]
    if qualification.get("label"):
        lines.append(f"Qualification automatique : {qualification['label']}")
    if hosts:
        lines.append("Machines : " + ", ".join(hosts[:10]))
    if details.get("sample_users"):
        lines.append("Comptes : " + ", ".join(str(u) for u in details["sample_users"][:10]))
    if details.get("sample_ips"):
        lines.append("Adresses IP : " + ", ".join(str(i) for i in details["sample_ips"][:10]))
    return {"subject": f"[Mini-SOC] {alert['title']}"[:200], "body": "\n".join(lines)}


async def node_for(redis: aioredis.Redis, hosts: list[str]) -> int | None:
    """Appareil NinjaOne du dernier relevé du parc, seulement si l'alerte vise une seule machine."""
    if len(hosts) != 1:
        return None
    wanted = hosts[0].strip().lower()
    for device_id, state in (await redis.hgetall(POSTURE_KEY)).items():
        if str(json.loads(state).get("name") or "").strip().lower() == wanted:
            return int(device_id)
    return None


def _listing(rows: list[dict], key: str = "name") -> str:
    return ", ".join(f"{r.get('id')} ({r.get(key)})" for r in rows[:15]) or "aucun"


async def test(cfg: dict) -> tuple[bool, str]:
    """Jeton, formulaires et organisations, en lecture : aucun ticket n'est créé par le bouton « Tester »."""
    if not has_credentials(cfg):
        return False, "Identifiant client ou secret manquant"
    async with httpx.AsyncClient(timeout=TIMEOUT) as http:
        api = TicketClient(cfg, http)
        try:
            forms = await api.request("GET", "/v2/ticketing/ticket-form")
            organizations = await api.request("GET", "/v2/organizations", params={"pageSize": 200})
        except TicketError as exc:
            return False, str(exc)
        except httpx.HTTPError as exc:
            return False, f"NinjaOne injoignable ({type(exc).__name__}) : instance {host(cfg)}"
    if forms.status_code >= 400:
        return False, f"Formulaires de tickets illisibles (HTTP {forms.status_code}) : module Ticketing activé ?"
    if organizations.status_code >= 400:
        return False, f"Organisations illisibles (HTTP {organizations.status_code})"
    form_rows, org_rows = forms.json() or [], organizations.json() or []
    form = next((f for f in form_rows if str(f.get("id")) == str(cfg.get("ninjaone_tickets_form_id"))), None)
    org = next((o for o in org_rows if str(o.get("id")) == str(cfg.get("ninjaone_tickets_org_id"))), None)
    if not form or not org:
        return False, f"À renseigner. Organisations : {_listing(org_rows)}. Formulaires : {_listing(form_rows)}."
    return True, (
        f"Connexion réussie : organisation « {org.get('name')} », formulaire « {form.get('name')} ». Aucun ticket créé."
    )
