"""Veille : catalogue CISA KEV (vulnérabilités activement exploitées) et flux RSS du CERT-FR.

Sources publiques, relues par le worker (KEV une fois par jour, CERT-FR toutes les 2 heures). Le serveur doit
pouvoir joindre www.cisa.gov et www.cert.ssi.gouv.fr en HTTPS.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import httpx
import redis.asyncio as aioredis
from defusedxml.ElementTree import fromstring

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CERTFR_FEEDS = {"alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/", "avis": "https://www.cert.ssi.gouv.fr/avis/feed/"}
KEV_KEY = "minisoc:kev"  # hash CVE -> fiche
KEV_META = "minisoc:kev:meta"
CERTFR_KEY = "minisoc:certfr"  # liste JSON des dernières publications
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
HEADERS = {"User-Agent": "Mini-SOC (veille securite)"}


async def refresh_kev(redis: aioredis.Redis) -> int:
    async with httpx.AsyncClient(timeout=60, headers=HEADERS, follow_redirects=True) as client:
        response = await client.get(KEV_URL)
        response.raise_for_status()
        data = response.json()
    entries = {}
    for v in data.get("vulnerabilities", []):
        cve = str(v.get("cveID", "")).upper()
        if CVE_RE.fullmatch(cve):
            entries[cve] = json.dumps({
                "cve": cve,
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "added": v.get("dateAdded", ""),
                "due": v.get("dueDate", ""),
                "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
                "description": str(v.get("shortDescription", ""))[:500],
            }, ensure_ascii=False)
    if not entries:
        raise ValueError("catalogue KEV vide ou illisible")
    pipe = redis.pipeline()
    pipe.delete(KEV_KEY)
    pipe.hset(KEV_KEY, mapping=entries)
    pipe.hset(KEV_META, mapping={"updated": datetime.now(timezone.utc).isoformat(),
                                 "catalog_version": str(data.get("catalogVersion", "")), "count": len(entries)})
    await pipe.execute()
    return len(entries)


def parse_rss(xml: str, kind: str) -> list[dict]:
    root = fromstring(xml)
    items = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        published = item.findtext("pubDate") or ""
        try:
            date = parsedate_to_datetime(published).astimezone(timezone.utc).isoformat()
        except (TypeError, ValueError):
            date = ""
        description = re.sub(r"<[^>]+>", " ", item.findtext("description") or "")
        items.append({
            "kind": kind,
            "title": title[:300],
            "link": (item.findtext("link") or "").strip()[:500],
            "date": date,
            "summary": re.sub(r"\s+", " ", description).strip()[:600],
            "cves": sorted({c.upper() for c in CVE_RE.findall(f"{title} {description}")}),
        })
    return items


async def refresh_certfr(redis: aioredis.Redis) -> int:
    items: list[dict] = []
    async with httpx.AsyncClient(timeout=30, headers=HEADERS, follow_redirects=True) as client:
        for kind, url in CERTFR_FEEDS.items():
            response = await client.get(url)
            response.raise_for_status()
            items += parse_rss(response.text, kind)
    items.sort(key=lambda i: i["date"], reverse=True)
    await redis.set(CERTFR_KEY, json.dumps(items[:60], ensure_ascii=False))
    return len(items)


class KevIndex:
    """Ensemble des CVE du catalogue KEV en mémoire, pour marquer les détections qui les mentionnent."""

    def __init__(self, redis: aioredis.Redis) -> None:
        self.redis = redis
        self.cves: set[str] = set()

    async def refresh(self) -> None:
        self.cves = set(await self.redis.hkeys(KEV_KEY))

    def match(self, *texts: str) -> list[str]:
        if not self.cves:
            return []
        found = {c.upper() for t in texts if t for c in CVE_RE.findall(t)}
        return sorted(found & self.cves)
