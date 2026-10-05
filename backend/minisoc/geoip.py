"""Enrichissement géographique des adresses IP publiques à partir de bases MMDB locales (aucun appel externe).

Déposer dans le dossier GeoIP (data/geoip/ sur l'hôte) l'un ou plusieurs de ces fichiers :
  - GeoLite2-City.mmdb ou GeoLite2-Country.mmdb (pays) et GeoLite2-ASN.mmdb (opérateur) — MaxMind, compte gratuit
  - dbip-country-lite-*.mmdb / dbip-city-lite-*.mmdb et dbip-asn-lite-*.mmdb — DB-IP, licence CC BY 4.0
Les bases sont relues automatiquement quand elles changent (mise à jour mensuelle conseillée).
"""

from __future__ import annotations

import ipaddress
import logging
import os
from functools import lru_cache
from pathlib import Path

import maxminddb

log = logging.getLogger(__name__)

COUNTRY_HINTS = ("city", "country")
ASN_HINTS = ("asn",)


class GeoIP:
    def __init__(self, directory: str) -> None:
        self.directory = Path(directory)
        self._country = None
        self._asn = None
        self._signature: tuple = ()
        self.reload()

    def files(self) -> list[str]:
        return [Path(path).name for path, _ in self._signature]

    @property
    def available(self) -> bool:
        return self._country is not None or self._asn is not None

    def _files(self) -> tuple[Path | None, Path | None]:
        if not self.directory.is_dir():
            return None, None
        files = sorted(self.directory.glob("*.mmdb"))
        country = next((f for f in files if any(h in f.name.lower() for h in COUNTRY_HINTS)), None)
        asn = next((f for f in files if any(h in f.name.lower() for h in ASN_HINTS)), None)
        return country, asn

    def reload(self) -> None:
        """Recharge les bases si un fichier a été ajouté ou mis à jour."""
        country, asn = self._files()
        signature = tuple((str(f), os.path.getmtime(f)) for f in (country, asn) if f)
        if signature == self._signature:
            return
        self._signature = signature
        try:
            self._country = maxminddb.open_database(str(country)) if country else None
            self._asn = maxminddb.open_database(str(asn)) if asn else None
            self.lookup.cache_clear()
            if signature:
                log.info("bases GeoIP chargées : %s", ", ".join(p for p, _ in signature))
        except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
            log.error("base GeoIP illisible : %s", exc)
            self._country = self._asn = None

    @lru_cache(maxsize=100_000)  # noqa: B019 - une seule instance par processus
    def lookup(self, ip: str) -> tuple[str, str]:
        """(code pays ISO, opérateur) d'une IP publique ; ("", "") si inconnue ou interne."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "", ""
        if not addr.is_global:
            return "", ""
        country = asn = ""
        if self._country is not None:
            record = self._country.get(ip) or {}
            country = str((record.get("country") or record.get("registered_country") or {}).get("iso_code") or "")
        if self._asn is not None:
            record = self._asn.get(ip) or {}
            asn = str(record.get("autonomous_system_organization") or record.get("as_org") or "")
            number = record.get("autonomous_system_number") or record.get("asn")
            if number and asn:
                asn = f"AS{number} {asn}"
        return country, asn[:120]
