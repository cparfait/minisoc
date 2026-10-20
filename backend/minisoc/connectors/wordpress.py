"""WordPress : versions installées, mises à jour à faire et failles connues des sites de la collectivité.

Chaque jour (ou sur « Analyser maintenant »), le worker interroge chaque site déclaré (HTTPS sortant) :
- **avec un mot de passe d'application** (compte administrateur du site, Utilisateurs › Profil) : liste exacte des
  extensions et thèmes par l'API REST (`/wp-json/wp/v2/plugins`, `/wp-json/wp/v2/themes`, lecture seule) ;
- **sans** : ce que le site montre publiquement (balise « generator », chemins `wp-content/plugins/…` de la page
  d'accueil, `readme.txt`, `style.css`), comme un scanner externe : la liste peut être incomplète.
La version du cœur vient de la balise « generator » (page d'accueil, flux RSS). Les dernières versions publiées
sont lues sur api.wordpress.org (extensions et thèmes de l'annuaire officiel ; une extension payante n'y figure
pas). Avec un jeton WPScan (offre gratuite : 25 requêtes par jour), les failles connues des versions installées
sont ajoutées ; une faille nouvelle donne une alerte (UC-63). Rien n'est modifié sur les sites.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from minisoc import bus
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

MODULE = "wordpress"
STATE_KEY = "minisoc:wordpress:sites"  # URL du site -> dernier inventaire (JSON)
STATUS_KEY = "minisoc:wordpress:status"  # dernière analyse : début, fin, erreurs (JSON)
SCAN_NOW_KEY = "minisoc:wordpress:scan_now"
LATEST_KEY = "minisoc:wordpress:latest"  # « plugin:slug » -> {version, at} (api.wordpress.org)
VULNS_KEY = "minisoc:wordpress:vulns"  # « plugin:slug » / « core:6.4.3 » -> {vulns, at} (WPScan)
WPSCAN_USED_PREFIX = "minisoc:wordpress:wpscan:"  # + date : requêtes WPScan du jour
CHECK_SECONDS = 60
SCAN_EVERY = timedelta(hours=24)
LATEST_TTL = timedelta(hours=12)
VULNS_TTL = timedelta(days=7)
MAX_SITES = 50
MAX_COMPONENTS = 80
WPSCAN_URL = "https://wpscan.com/api/v3"
WPORG_URL = "https://api.wordpress.org"
USER_AGENT = "Mini-SOC (inventaire WordPress, lecture seule)"
KINDS = {"core": "WordPress", "plugin": "Extension", "theme": "Thème"}

_GENERATOR = (re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress ([0-9][0-9.]*)", re.I),
              re.compile(r"<generator>https?://wordpress\.org/\?v=([0-9][0-9.]*)</generator>", re.I))
_ASSET = re.compile(r"/wp-content/(plugins|themes)/([a-z0-9][a-z0-9_.-]{0,80})/([^\"'\s)>]*)", re.I)
_VER_PARAM = re.compile(r"[?&](?:amp;)?ver=([0-9][0-9a-z.\-]{0,30})", re.I)
_STABLE_TAG = re.compile(r"^\s*Stable tag:\s*([0-9][0-9a-z.\-]*)", re.I | re.M)
_STYLE_VERSION = re.compile(r"^\s*\*?\s*Version:\s*([0-9][0-9a-z.\-]*)", re.I | re.M)


class WordPressError(RuntimeError):
    pass


# ---------- Paramètres ----------

def sites(cfg: dict) -> list[dict]:
    """Sites déclarés : [{url, user, password}] (JSON chiffré du paramètre wordpress_sites)."""
    try:
        raw = json.loads(cfg.get("wordpress_sites") or "[]")
    except ValueError:
        return []
    out = []
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, dict) and item.get("url"):
            out.append({"url": normalize_url(str(item["url"])), "user": str(item.get("user") or ""),
                        "password": str(item.get("password") or "")})
    return out[:MAX_SITES]


def normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parts = urlsplit(url)
    if not parts.hostname:
        raise WordPressError(f"adresse invalide : {url}")
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path.rstrip('/')}"


def site_name(url: str) -> str:
    parts = urlsplit(url)
    return (parts.hostname or url) + (parts.path if parts.path not in ("", "/") else "")


def configured(cfg: dict) -> bool:
    return bool(sites(cfg))


def make_http(cfg: dict) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=30, follow_redirects=True, headers={"User-Agent": USER_AGENT},
                             verify=bool(cfg.get("wordpress_verify_tls", True)))


# ---------- Versions ----------

def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", version or "")[:4])


def newer(latest: str, installed: str) -> bool:
    return bool(latest and installed and version_key(latest) > version_key(installed))


def update_kind(latest: str, installed: str) -> str:
    """« correctif » dans la même branche (6.4.3 → 6.4.5), sinon « version »."""
    if not newer(latest, installed):
        return ""
    return "correctif" if version_key(latest)[:2] == version_key(installed)[:2] else "version"


def affected(vuln: dict, installed: str) -> bool:
    """Faille WPScan présente dans la version installée (corrigée après elle, introduite avant ou inconnue)."""
    if not installed:
        return False
    fixed, introduced = str(vuln.get("fixed_in") or ""), str(vuln.get("introduced_in") or "")
    if fixed and version_key(installed) >= version_key(fixed):
        return False
    return not (introduced and version_key(installed) < version_key(introduced))


def compact_vuln(vuln: dict) -> dict:
    refs = vuln.get("references") if isinstance(vuln.get("references"), dict) else {}
    cves = [f"CVE-{c}" if not str(c).upper().startswith("CVE-") else str(c).upper() for c in refs.get("cve") or []]
    cvss = vuln.get("cvss") if isinstance(vuln.get("cvss"), dict) else {}
    try:
        score = float(cvss.get("score")) if cvss.get("score") is not None else None
    except (TypeError, ValueError):
        score = None
    return {"id": str(vuln.get("id") or vuln.get("title") or "")[:64], "title": str(vuln.get("title") or "")[:200],
            "fixed_in": str(vuln.get("fixed_in") or "")[:30],
            "introduced_in": str(vuln.get("introduced_in") or "")[:30],
            "type": str(vuln.get("vuln_type") or "")[:40], "cves": cves[:5], "score": score}


# ---------- Lecture d'un site ----------

class SiteReader:
    def __init__(self, http: httpx.AsyncClient, site: dict) -> None:
        self.http = http
        self.url = site["url"]
        self.auth = (site["user"], site["password"]) if site.get("user") and site.get("password") else None

    async def _get(self, path: str, **kw) -> httpx.Response:
        return await self.http.get(self.url + path, **kw)

    async def rest(self, route: str) -> list[dict]:
        """Route de l'API REST, avec repli sur ?rest_route= (permaliens « simples »)."""
        response = await self._get(f"/wp-json{route}", auth=self.auth, params={"per_page": 100})
        if response.status_code == 404:
            response = await self._get("/", auth=self.auth, params={"rest_route": route, "per_page": 100})
        if response.status_code in (401, 403):
            raise WordPressError("identifiant ou mot de passe d'application refusé (compte administrateur requis)")
        if response.status_code == 404:
            raise WordPressError("API REST introuvable (désactivée par une extension de sécurité ?)")
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            raise WordPressError("réponse inattendue de l'API REST")
        return data

    async def core_version(self, home: str) -> str:
        for pattern in _GENERATOR[:1]:
            if m := pattern.search(home):
                return m.group(1)
        for path in ("/feed/", "/?feed=rss2"):
            try:
                response = await self._get(path)
            except httpx.HTTPError:
                continue
            if response.status_code == 200 and (m := _GENERATOR[1].search(response.text)):
                return m.group(1)
        return ""

    async def inventory(self) -> dict:
        response = await self._get("/")
        response.raise_for_status()
        home = response.text
        core = await self.core_version(home)
        if self.auth:
            plugins = [{"slug": str(p.get("plugin") or "").split("/")[0], "name": _text(p.get("name")),
                        "installed": str(p.get("version") or ""),
                        "active": p.get("status") in ("active", "network-active")}
                       for p in await self.rest("/wp/v2/plugins")]
            themes = [{"slug": str(t.get("stylesheet") or ""), "name": _text(t.get("name")),
                       "installed": str(t.get("version") or ""), "active": t.get("status") == "active"}
                      for t in await self.rest("/wp/v2/themes")]
            mode = "api"
        else:
            plugins, themes = await self.public_components(home)
            mode = "public"
        return {"core": core, "plugins": [p for p in plugins if p["slug"]][:MAX_COMPONENTS],
                "themes": [t for t in themes if t["slug"]][:MAX_COMPONENTS], "mode": mode}

    async def public_components(self, home: str) -> tuple[list[dict], list[dict]]:
        """Extensions et thèmes visibles dans la page d'accueil ; version lue dans readme.txt ou style.css."""
        found: dict[tuple[str, str], str] = {}
        for m in _ASSET.finditer(home):
            kind, slug = m.group(1).lower(), m.group(2).lower()
            ver = _VER_PARAM.search(m.group(3))
            found.setdefault((kind, slug), ver.group(1) if ver else "")
        plugins, themes = [], []
        for (kind, slug), hint in list(found.items())[:MAX_COMPONENTS]:
            path, pattern = (("readme.txt", _STABLE_TAG) if kind == "plugins" else ("style.css", _STYLE_VERSION))
            version = ""
            try:
                response = await self._get(f"/wp-content/{kind}/{slug}/{path}")
                if response.status_code == 200 and (m := pattern.search(response.text[:20000])):
                    version = m.group(1)
            except httpx.HTTPError:
                pass
            entry = {"slug": slug, "name": slug, "installed": version or hint, "active": True}
            (plugins if kind == "plugins" else themes).append(entry)
        return plugins, themes


def _text(value) -> str:
    if isinstance(value, dict):
        value = value.get("rendered") or value.get("raw") or ""
    return re.sub(r"<[^>]+>", "", str(value or ""))[:120]


# ---------- Dernières versions (api.wordpress.org) et failles (WPScan) ----------

class Catalog:
    """Dernières versions publiées et failles connues, avec cache Redis (et quota WPScan quotidien)."""

    def __init__(self, http: httpx.AsyncClient, redis: aioredis.Redis, cfg: dict, now: datetime) -> None:
        self.http = http
        self.redis = redis
        self.token = str(cfg.get("wordpress_wpscan_token") or "").strip()
        self.budget = int(cfg.get("wordpress_wpscan_daily") or 25)
        self.now = now
        self.core_latest: str | None = None
        self.quota_reached = False

    async def _cached(self, key: str, field: str, ttl: timedelta) -> dict | None:
        raw = await self.redis.hget(key, field)
        if not raw:
            return None
        data = json.loads(raw)
        return data if self.now - datetime.fromisoformat(data["at"]) < ttl else None

    async def _store(self, key: str, field: str, data: dict) -> None:
        await self.redis.hset(key, field, json.dumps({**data, "at": self.now.isoformat()}, ensure_ascii=False))

    async def latest(self, kind: str, slug: str) -> str:
        if kind == "core":
            if self.core_latest is None:
                cached = await self._cached(LATEST_KEY, "core", LATEST_TTL)
                if cached is None:
                    try:
                        response = await self.http.get(f"{WPORG_URL}/core/version-check/1.7/")
                        response.raise_for_status()
                        offers = response.json().get("offers") or [{}]
                    except (httpx.HTTPError, ValueError):
                        return ""  # réessayé au passage suivant
                    cached = {"version": str(offers[0].get("current") or offers[0].get("version") or "")}
                    await self._store(LATEST_KEY, "core", cached)
                self.core_latest = cached["version"]
            return self.core_latest
        cached = await self._cached(LATEST_KEY, f"{kind}:{slug}", LATEST_TTL)
        if cached is None:
            section = "plugins" if kind == "plugin" else "themes"
            action = "plugin_information" if kind == "plugin" else "theme_information"
            try:
                response = await self.http.get(f"{WPORG_URL}/{section}/info/1.2/",
                                               params={"action": action, "request[slug]": slug})
                data = response.json() if response.status_code in (200, 404) else {}
            except (httpx.HTTPError, ValueError):
                return ""  # réessayé au passage suivant
            cached = {"version": str(data.get("version") or "") if isinstance(data, dict) else ""}
            await self._store(LATEST_KEY, f"{kind}:{slug}", cached)
        return cached["version"]

    async def vulns(self, kind: str, slug: str, installed: str) -> list[dict] | None:
        """Failles WPScan touchant la version installée ; None si inconnu (pas de jeton, quota atteint)."""
        if not self.token or not installed:
            return None
        field = f"core:{installed}" if kind == "core" else f"{kind}:{slug}"
        cached = await self._cached(VULNS_KEY, field, VULNS_TTL)
        if cached is None:
            if self.quota_reached or not await self._spend():
                self.quota_reached = True
                return None
            path = (f"wordpresses/{''.join(re.findall(r'\d', installed))}" if kind == "core"
                    else f"{kind}s/{slug}")
            response = await self.http.get(f"{WPSCAN_URL}/{path}",
                                           headers={"Authorization": f"Token token={self.token}"})
            if response.status_code in (401, 403):
                raise WordPressError("jeton WPScan refusé")
            if response.status_code == 429:
                self.quota_reached = True
                return None
            if response.status_code == 404:
                found: list[dict] = []
            else:
                response.raise_for_status()
                body = response.json() or {}
                entry = next(iter(body.values()), {}) if isinstance(body, dict) and body else {}
                found = [compact_vuln(v) for v in (entry or {}).get("vulnerabilities") or []]
            cached = {"vulns": found}
            await self._store(VULNS_KEY, field, cached)
        if kind == "core":
            return cached["vulns"]  # déjà propres à cette version
        return [v for v in cached["vulns"] if affected(v, installed)]

    async def _spend(self) -> bool:
        key = WPSCAN_USED_PREFIX + self.now.strftime("%Y-%m-%d")
        used = await self.redis.incr(key)
        await self.redis.expire(key, 2 * 86400)
        return used <= self.budget


async def scan_site(http: httpx.AsyncClient, catalog: Catalog, site: dict) -> dict:
    """Inventaire d'un site, complété des dernières versions et des failles connues."""
    found = await SiteReader(http, site).inventory()
    components = [{"kind": "core", "slug": "wordpress", "name": "WordPress", "installed": found["core"],
                   "active": True}]
    components += [{"kind": "plugin", **p} for p in found["plugins"]]
    components += [{"kind": "theme", **t} for t in found["themes"]]
    for c in components:
        c["latest"] = await catalog.latest(c["kind"], c["slug"])
        c["update"] = update_kind(c["latest"], c["installed"])
        c["vulns"] = await catalog.vulns(c["kind"], c["slug"], c["installed"])
    return {"url": site["url"], "name": site_name(site["url"]), "mode": found["mode"],
            "scanned_at": catalog.now.isoformat(), "error": "", "components": components,
            "vulns_checked": bool(catalog.token)}


def counts(state: dict) -> dict:
    comps = state.get("components") or []
    core = next((c for c in comps if c["kind"] == "core"), {})
    return {
        "core": core.get("installed") or "", "core_latest": core.get("latest") or "",
        "updates": sum(1 for c in comps if c.get("update")),
        "plugins": sum(1 for c in comps if c["kind"] == "plugin"),
        "themes": sum(1 for c in comps if c["kind"] == "theme"),
        "vulnerable": sum(1 for c in comps if c.get("vulns")),
        "vulns": sum(len(c.get("vulns") or []) for c in comps),
    }


def findings(previous: dict | None, current: dict) -> list[dict]:
    """Failles apparues depuis l'inventaire précédent : un message par site."""
    def keys(state: dict | None) -> set[str]:
        return {f"{c['kind']}:{c['slug']}:{v['id']}" for c in (state or {}).get("components") or []
                for v in c.get("vulns") or []}

    new = keys(current) - keys(previous)
    if not new:
        return []
    items = []
    for c in current["components"]:
        fresh = [v for v in c.get("vulns") or [] if f"{c['kind']}:{c['slug']}:{v['id']}" in new]
        if fresh:
            fixed = max((v["fixed_in"] for v in fresh if v["fixed_in"]), key=version_key, default="")
            items.append({"kind": c["kind"], "slug": c["slug"], "name": c["name"], "installed": c["installed"],
                          "fixed_in": fixed, "latest": c["latest"],
                          "titles": [v["title"] for v in fresh][:3],
                          "cves": sorted({cve for v in fresh for cve in v["cves"]})[:10],
                          "score": max((v["score"] for v in fresh if v["score"] is not None), default=None)})
    return [{"type": "findings", "kind": "vulnerable_component", "site": current["url"], "name": current["name"],
             "count": len(new), "items": items[:20]}]


def load_states(raw: dict) -> dict[str, dict]:
    out = {}
    for key, value in (raw or {}).items():
        try:
            out[key] = json.loads(value)
        except ValueError:
            continue
    return out


def summary(state: dict) -> dict:
    return {"url": state.get("url"), "name": state.get("name"), "mode": state.get("mode"),
            "scanned_at": state.get("scanned_at"), "error": state.get("error") or "",
            "vulns_checked": bool(state.get("vulns_checked")), **counts(state)}


# ---------- Tâche du worker ----------

class WordPressJob:
    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis) -> None:
        self.sessions = sessions
        self.redis = redis

    async def run(self) -> None:
        while True:
            try:
                async with self.sessions() as session:
                    cfg = await settings_store.load(session)
                if cfg.get("src_wordpress_enabled", False) and configured(cfg) and await self.due():
                    await self.scan(cfg)
            except Exception:  # noqa: BLE001 - la tâche continue au passage suivant
                log.exception("WordPress : analyse en échec")
            await asyncio.sleep(CHECK_SECONDS)

    async def due(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        if await self.redis.get(SCAN_NOW_KEY):
            return True
        status = json.loads(await self.redis.get(STATUS_KEY) or "{}")
        return not status.get("finished") or now - datetime.fromisoformat(status["finished"]) >= SCAN_EVERY

    async def scan(self, cfg: dict, now: datetime | None = None) -> dict:
        now = now or datetime.now(timezone.utc)
        await self.redis.delete(SCAN_NOW_KEY)
        await self.redis.set(STATUS_KEY, json.dumps({"state": "running", "started": now.isoformat()}))
        declared = sites(cfg)
        errors: list[str] = []
        published = 0
        async with make_http(cfg) as http:
            catalog = Catalog(http, self.redis, cfg, now)
            for site in declared:
                raw = await self.redis.hget(STATE_KEY, site["url"])
                previous = json.loads(raw) if raw else None
                try:
                    current = await scan_site(http, catalog, site)
                except (WordPressError, httpx.HTTPError, ValueError) as exc:
                    reason = str(exc) if isinstance(exc, WordPressError) else _http_reason(exc)
                    errors.append(f"{site_name(site['url'])} : {reason}")
                    current = {**(previous or {"url": site["url"], "name": site_name(site["url"]), "components": []}),
                               "error": reason, "checked_at": now.isoformat()}
                    await self.redis.hset(STATE_KEY, site["url"], json.dumps(current, ensure_ascii=False))
                    continue
                records = findings(previous, current)
                published += await bus.publish(self.redis, MODULE,
                                               [json.dumps(r, ensure_ascii=False) for r in records])
                await self.redis.hset(STATE_KEY, site["url"], json.dumps(current, ensure_ascii=False))
        known = {s["url"] for s in declared}
        for url in await self.redis.hkeys(STATE_KEY):  # site retiré de la liste : son inventaire aussi
            if url not in known:
                await self.redis.hdel(STATE_KEY, url)
        if len(errors) < len(declared):
            await bus.heartbeat(self.redis, MODULE)
        status = {"state": "error" if errors and len(errors) == len(declared) else "ok", "started": now.isoformat(),
                  "finished": datetime.now(timezone.utc).isoformat(), "sites": len(declared), "errors": errors,
                  "quota_reached": catalog.quota_reached}
        await self.redis.set(STATUS_KEY, json.dumps(status, ensure_ascii=False))
        log.info("WordPress : %d site(s) analysé(s), %d en échec, %d alerte(s)", len(declared), len(errors), published)
        return status


def _http_reason(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    if isinstance(exc, httpx.HTTPError):
        return f"site injoignable ({type(exc).__name__})"
    return f"réponse illisible ({exc})"


async def test(cfg: dict, redis: aioredis.Redis) -> tuple[bool, str]:
    """Bouton « Tester » : inventaire du premier site, sans rien enregistrer ni alerter."""
    declared = sites(cfg)
    if not declared:
        return False, "Aucun site déclaré : ajouter un site ci-dessous (Configuration)"
    site = declared[0]
    try:
        async with make_http(cfg) as http:
            found = await SiteReader(http, site).inventory()
    except WordPressError as exc:
        return False, f"{site_name(site['url'])} : {exc}"
    except (httpx.HTTPError, ValueError) as exc:
        return False, f"{site_name(site['url'])} : {_http_reason(exc)}"
    how = "API REST (liste exacte)" if found["mode"] == "api" else "détection publique (liste peut-être incomplète)"
    return True, (f"{site_name(site['url'])} : WordPress {found['core'] or 'version masquée'}, "
                  f"{len(found['plugins'])} extension(s), {len(found['themes'])} thème(s) — {how}")
