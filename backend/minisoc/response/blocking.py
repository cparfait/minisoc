"""Blocage d'adresses IP : contrôles (jamais d'IP interne ou protégée), exécution sur le pare-feu, expiration."""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.models import Block
from minisoc.response.xgs import XGSClient, XGSError

log = logging.getLogger(__name__)
MAX_PER_REQUEST = 500


def check_ip(ip: str, never_block: list[str]) -> str | None:
    """Retourne la raison du refus, ou None si l'adresse peut être bloquée."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return "adresse IP invalide"
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved \
            or addr.is_unspecified:
        # Plages de documentation (RFC 5737) tolérées : elles servent aux tests de recette
        if not any(addr in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
            return "adresse interne ou réservée"
    for net in never_block:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return f"protégée (liste « jamais bloquer » : {net})"
        except ValueError:
            continue
    return None


async def block_ips(db: AsyncSession, cfg: dict, ips: list[str], hours: int, reason: str, actor: str,
                    actor_ip: str, alert_id: int | None) -> dict:
    """Bloque chaque IP valide. Retourne {"blocked": [...], "refused": {ip: raison}, "failed": {ip: erreur}}."""
    if not cfg.get("response_enabled"):
        raise XGSError("Actions de réponse désactivées (Paramètres > Réponse)")
    client = XGSClient(cfg)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=hours)
    active = {b.ip for b in (await db.scalars(select(Block).where(Block.status == "active"))).all()}
    result: dict = {"blocked": [], "already": [], "refused": {}, "failed": {}}
    for ip in dict.fromkeys(i.strip() for i in ips[:MAX_PER_REQUEST] if i.strip()):
        refusal = check_ip(ip, cfg.get("never_block") or [])
        if refusal:
            result["refused"][ip] = refusal
            continue
        if ip in active:
            result["already"].append(ip)
            continue
        try:
            await client.block(ip)
        except XGSError as exc:
            result["failed"][ip] = str(exc)
            db.add(Block(ip=ip, reason=reason[:512], alert_id=alert_id, status="failed", detail=str(exc)[:1000],
                         created_by=actor, expires_at=expires))
            if "Connexion à l'API refusée" in str(exc) or "injoignable" in str(exc):
                break  # inutile d'insister pour les IP suivantes
            continue
        db.add(Block(ip=ip, reason=reason[:512], alert_id=alert_id, created_by=actor, expires_at=expires))
        result["blocked"].append(ip)
    await audit.record(db, actor=actor, ip=actor_ip, action="ip_block", obj=f"alert:{alert_id}" if alert_id else "",
                       detail={"blocked": result["blocked"], "refused": result["refused"],
                               "failed": list(result["failed"]), "hours": hours})
    await db.commit()
    return result


async def unblock(db: AsyncSession, cfg: dict, block: Block, actor: str, actor_ip: str = "") -> None:
    await XGSClient(cfg).unblock(block.ip)
    block.status = "removed"
    block.removed_at = datetime.now(timezone.utc)
    block.removed_by = actor
    await audit.record(db, actor=actor, ip=actor_ip, action="ip_unblock", obj=f"block:{block.id}",
                       detail={"ip": block.ip})
    await db.commit()


async def expire_blocks(db: AsyncSession, cfg: dict) -> int:
    """Lève les blocages arrivés à échéance (appelé chaque minute par le worker)."""
    now = datetime.now(timezone.utc)
    due = (await db.scalars(select(Block).where(Block.status == "active", Block.expires_at <= now).limit(100))).all()
    done = 0
    for block in due:
        try:
            await unblock(db, cfg, block, actor="expiration")
            done += 1
        except XGSError as exc:
            log.error("levée du blocage %s (%s) en échec : %s", block.id, block.ip, exc)
            break
    return done
