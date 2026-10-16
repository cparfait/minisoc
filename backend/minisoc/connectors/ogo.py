"""OGO Security (WAF) : journal des événements et état des sites, lus par l'API v2 (lecture seule, flux sortant).

OGO ne donne pas le détail requête par requête par l'API ; il fournit :
- GET /v2/organizations/{code}/journal : événements de sécurité (pic de bannissements, afflux de trafic,
  limitation de débit), de surveillance (erreurs 5xx, certificat, DNS) et d'activité (configuration des sites,
  utilisateurs, paramètres de protection), triés par date ; relus depuis le dernier événement vu ;
- GET /v2/organizations/{code}/sites puis /sites/{domaine} : état de chaque site, chaque heure ; un message n'est
  publié qu'au changement (protection contournée « passthrough », mode audit, site hors ligne…).

Authentification (fournisseur Terraform officiel d'OGO) : en-tête `X-Ogo-Auth: <e-mail>;md5(<chemin>-<clé>)`, le
chemin de l'URL sans paramètres. La clé ne circule jamais. Clé d'API d'un compte OGO au rôle « Viewer » de
préférence (Mon compte › Mon profil › Authentification › Clé d'API) ; rien n'est modifié dans OGO.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from minisoc import bus
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

MODULE = "ogo"
DEFAULT_URL = "https://api.ogosecurity.com"
CURSOR_KEY = "minisoc:cursor:ogo:journal"  # date du dernier événement du journal lu (ISO)
SEEN_PREFIX = "minisoc:seen:ogo:"
SEEN_TTL = 30 * 86400
SITES_KEY = "minisoc:ogo:sites"  # état connu de chaque site (JSON), pour ne publier que les changements
SITES_CHECKED_KEY = "minisoc:ogo:sites:checked"
POLL_SECONDS = 60
SITES_SECONDS = 3600
FIRST_DAYS = 7  # premier passage : journal des 7 derniers jours
OVERLAP = timedelta(minutes=5)  # relecture d'une marge : les événements déjà vus sont écartés
PAGE = 100
MAX_PAGES = 20
SITE_FIELDS = ("status", "auditMode", "passthroughMode", "mode", "cluster")


class OgoError(RuntimeError):
    pass


def base_url(cfg: dict) -> str:
    url = str(cfg.get("ogo_api_url") or DEFAULT_URL).strip().rstrip("/")
    if not url.startswith("https://"):
        url = "https://" + url.removeprefix("http://")
    return url


def configured(cfg: dict) -> bool:
    return bool(cfg.get("ogo_email") and cfg.get("ogo_api_key"))


def make_http(cfg: dict) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=60, headers={"Accept": "application/json"})


def auth_header(email: str, api_key: str, path: str) -> str:
    return f"{email};{hashlib.md5(f'{path}-{api_key}'.encode()).hexdigest()}"  # noqa: S324 - imposé par OGO


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class OgoClient:
    def __init__(self, cfg: dict, http: httpx.AsyncClient) -> None:
        self.cfg = cfg
        self.http = http
        self.base = base_url(cfg)
        self.organization = str(cfg.get("ogo_organization") or "").strip()

    async def get(self, path: str, params: dict | None = None):
        url = httpx.URL(f"{self.base}{path}")
        header = auth_header(str(self.cfg["ogo_email"]).strip(), str(self.cfg["ogo_api_key"]).strip(), url.path)
        response = await self.http.get(url, params=params, headers={"X-Ogo-Auth": header})
        if response.status_code == 401:
            raise OgoError("e-mail ou clé d'API refusés par OGO (clé désactivée ou régénérée ?)")
        if response.status_code == 403:
            raise OgoError(f"accès refusé par OGO à {url.path} (droits du compte dans l'organisation)")
        response.raise_for_status()
        return response.json() if response.content else {}

    async def org(self) -> str:
        """Code de l'organisation : celui saisi, sinon la seule organisation du compte."""
        if self.organization:
            return self.organization
        data = await self.get("/v2/organizations", {"size": 50})
        codes = [str((o.get("organization") or {}).get("code") or "") for o in data.get("content") or []]
        codes = [c for c in codes if c]
        if len(codes) != 1:
            raise OgoError("plusieurs organisations sur ce compte OGO : saisir le code de l'organisation "
                           f"({', '.join(codes)})" if codes else "aucune organisation sur ce compte OGO")
        self.organization = codes[0]
        return self.organization

    async def journal(self, after: datetime, page: int = 0, size: int = PAGE) -> dict:
        # Objet de requête « EventQuery » : ses champs passent à plat dans l'URL (after, before, type…)
        return await self.get(f"/v2/organizations/{await self.org()}/journal",
                              {"after": _iso(after), "page": page, "size": size, "sort": "date,asc"})

    async def sites(self) -> list[str]:
        names, page = [], 0
        while page < MAX_PAGES:
            data = await self.get(f"/v2/organizations/{await self.org()}/sites", {"page": page, "size": PAGE})
            names += [str(s.get("domainName")) for s in data.get("content") or [] if s.get("domainName")]
            if data.get("last", True):
                break
            page += 1
        return names

    async def site(self, domain: str) -> dict:
        return await self.get(f"/v2/organizations/{await self.org()}/sites/{domain}")


def site_state(config: dict) -> dict:
    """Champs suivis d'un site : ceux dont le changement intéresse la sécurité."""
    state = {k: config.get(k) for k in SITE_FIELDS}
    state["cluster"] = (config.get("cluster") or {}).get("name") if isinstance(config.get("cluster"), dict) else None
    return state


class OgoConnector:
    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis) -> None:
        self.sessions = sessions
        self.redis = redis

    async def run(self) -> None:
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            if configured(cfg) and cfg.get("src_ogo_enabled", False):
                try:
                    async with make_http(cfg) as http:
                        api = OgoClient(cfg, http)
                        count = await self.poll(api)
                        count += await self.check_sites(api)
                    await bus.heartbeat(self.redis, MODULE)
                    if count:
                        log.info("OGO : %d nouvel(s) événement(s)", count)
                except OgoError as exc:
                    log.error("OGO : %s", exc)
                except Exception as exc:  # noqa: BLE001
                    log.error("OGO : interrogation en échec : %s", exc)
            await asyncio.sleep(POLL_SECONDS)

    async def poll(self, api: OgoClient, now: datetime | None = None) -> int:
        """Journal depuis le dernier événement lu (moins une marge), page par page, sans doublon."""
        now = now or datetime.now(timezone.utc)
        saved = await self.redis.get(CURSOR_KEY)
        after = datetime.fromisoformat(saved) - OVERLAP if saved else now - timedelta(days=FIRST_DAYS)
        organization = await api.org()
        published, latest = 0, saved
        for page in range(MAX_PAGES):
            data = await api.journal(after, page)
            fresh = []
            for event in data.get("content") or []:
                event_id = str(event.get("id") or "")
                if event_id and await self.redis.set(f"{SEEN_PREFIX}{event_id}", 1, nx=True, ex=SEEN_TTL):
                    fresh.append(json.dumps({"type": "journal", "organization": organization, "event": event},
                                            ensure_ascii=False, default=str))
                date = str(event.get("date") or "")
                if date and (latest is None or _after(date, latest)):
                    latest = date
            published += await bus.publish(self.redis, MODULE, fresh)
            if data.get("last", True) or not data.get("content"):
                break
        if latest and latest != saved:
            await self.redis.set(CURSOR_KEY, _normalize(latest))
        return published

    async def check_sites(self, api: OgoClient, now: datetime | None = None, force: bool = False) -> int:
        """Toutes les heures : état de chaque site ; un message par site nouveau ou modifié."""
        now = now or datetime.now(timezone.utc)
        checked = await self.redis.get(SITES_CHECKED_KEY)
        if not force and checked and now - datetime.fromisoformat(checked) < timedelta(seconds=SITES_SECONDS):
            return 0
        known = json.loads(await self.redis.get(SITES_KEY) or "{}")
        current, fresh = {}, []
        for domain in await api.sites():
            state = site_state(await api.site(domain))
            current[domain] = state
            if known.get(domain) != state:
                fresh.append(json.dumps({"type": "site", "organization": api.organization, "site": domain,
                                         "state": state, "previous": known.get(domain)}, ensure_ascii=False))
        await self.redis.set(SITES_KEY, json.dumps(current, ensure_ascii=False))
        await self.redis.set(SITES_CHECKED_KEY, now.isoformat())
        return await bus.publish(self.redis, MODULE, fresh)


def _normalize(date: str) -> str:
    return datetime.fromisoformat(date.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()


def _after(date: str, reference: str) -> bool:
    try:
        return datetime.fromisoformat(date.replace("Z", "+00:00")) > datetime.fromisoformat(
            reference.replace("Z", "+00:00"))
    except ValueError:
        return False


async def test(cfg: dict) -> tuple[bool, str]:
    """Organisation, sites et journal des dernières 24 h (lecture seule) : bouton « Tester »."""
    if not configured(cfg):
        return False, "E-mail du compte OGO ou clé d'API manquant"
    try:
        async with make_http(cfg) as http:
            api = OgoClient(cfg, http)
            organization = await api.org()
            sites = await api.sites()
            journal = await api.journal(datetime.now(timezone.utc) - timedelta(days=1), size=1)
    except OgoError as exc:
        return False, str(exc)
    except httpx.HTTPStatusError as exc:
        hint = " (code d'organisation inconnu ?)" if exc.response.status_code == 404 else ""
        return False, f"OGO : HTTP {exc.response.status_code}{hint}"
    except httpx.HTTPError as exc:
        return False, f"OGO injoignable ({type(exc).__name__}) : {base_url(cfg)}"
    return True, (f"Connexion réussie à l'organisation {organization} : {len(sites)} site(s) protégé(s), "
                  f"{int(journal.get('totalElements') or 0)} événement(s) au journal ces dernières 24 h")
