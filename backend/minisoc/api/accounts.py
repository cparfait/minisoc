"""Comptes AD : comptes verrouillés (et d'où viennent les échecs), comptes sensibles et leur activité."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.accounts import ad_configured, directory, sync_from_ad, sync_status
from minisoc.api.deps import ADMIN, ANY_USER, client_ip, get_db
from minisoc.models import User
from minisoc.settings_store import store as settings_store

router = APIRouter(tags=["accounts"])

LOGON = "category = 'authentication' AND action = 'logon' AND outcome = 'success'"
FAILURE = "category = 'authentication' AND outcome = 'failure'"


def _iso(value) -> str | None:
    """Date ClickHouse (naïve, UTC) → ISO ; la valeur par défaut d'un maxIf vide (1970) → None."""
    if not isinstance(value, datetime) or value.year < 2000:
        return None
    return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value).isoformat()


async def _lockouts(store, hours: int) -> list[dict]:
    rows = await store.query(
        "SELECT lower(user_name) AS name, any(user_name) AS user, any(user_roles) AS roles, count() AS lockouts, "
        "max(ts) AS locked_at, argMax(host_name, ts) AS caller FROM events WHERE module = 'windows' "
        "AND action = 'account_locked' AND user_name != '' AND ts >= now64(3) - toIntervalHour({h:UInt32}) "
        "GROUP BY name ORDER BY locked_at DESC LIMIT 500",
        {"h": hours},
    )
    if not rows:
        return []
    names = [r["name"] for r in rows]
    cleared = {r["name"]: r for r in await store.query(
        "SELECT lower(user_name) AS name, maxIf(ts, action = 'account_unlocked') AS unlocked, "
        f"argMaxIf(threat_name, ts, action = 'account_unlocked') AS unlocked_by, maxIf(ts, {LOGON}) AS logon "
        "FROM events WHERE module = 'windows' AND lower(user_name) IN {n:Array(String)} "
        "AND ts >= now64(3) - toIntervalHour({h:UInt32}) GROUP BY name",
        {"n": names, "h": hours},
    )}
    origins: dict[str, list[dict]] = {}
    for r in await store.query(
        "SELECT lower(user_name) AS name, host_name, source_ip, network_service, count() AS failures, "
        f"max(ts) AS last FROM events WHERE module = 'windows' AND {FAILURE} "
        "AND lower(user_name) IN {n:Array(String)} AND ts >= now64(3) - toIntervalHour({h:UInt32}) "
        "GROUP BY name, host_name, source_ip, network_service ORDER BY failures DESC LIMIT 3 BY name",
        {"n": names, "h": hours},
    ):
        origins.setdefault(r["name"], []).append({
            "host": r["host_name"], "ip": r["source_ip"], "service": r["network_service"],
            "failures": r["failures"], "last": _iso(r["last"]),
        })
    out = []
    for r in rows:
        c = cleared.get(r["name"], {})
        unlocked, logon = c.get("unlocked"), c.get("logon")
        locked_at = r["locked_at"]
        still = not any(isinstance(v, datetime) and v.year >= 2000 and v > locked_at for v in (unlocked, logon))
        out.append({
            "user": r["user"], "roles": r["roles"], "lockouts": r["lockouts"], "locked_at": _iso(locked_at),
            "caller": r["caller"], "still_locked": still, "unlocked_at": _iso(unlocked),
            "unlocked_by": (c.get("unlocked_by") or "").removeprefix("par "), "last_logon": _iso(logon),
            "origins": origins.get(r["name"], []),
        })
    return out


async def _activity(store, days: int) -> dict[str, dict]:
    rows = await store.query(
        "SELECT lower(user_name) AS name, any(user_name) AS user, any(user_roles) AS roles, "
        f"countIf({LOGON}) AS logons, countIf({FAILURE}) AS failures, "
        "countIf(action = 'account_locked') AS lockouts, "
        f"maxIf(ts, {LOGON}) AS last_logon, argMaxIf(host_name, ts, {LOGON}) AS last_host, "
        f"argMaxIf(network_service, ts, {LOGON}) AS last_service, uniqExactIf(host_name, {LOGON}) AS hosts "
        "FROM events WHERE module = 'windows' AND user_roles != '' "
        "AND ts >= now64(3) - toIntervalDay({d:UInt32}) GROUP BY name LIMIT 2000",
        {"d": days},
    )
    return {r["name"]: r for r in rows}


@router.get("/api/accounts")
async def accounts_overview(request: Request, db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    state = request.app.state
    cfg = await settings_store.load(db)
    known = await directory(state.redis)
    activity = await _activity(state.store, 7)
    names = set(known) | set(activity)
    sensitive = []
    for name in names:
        info, act = known.get(name, {}), activity.get(name, {})
        roles = info.get("roles") or [r for r in (act.get("roles") or "").split(",") if r]
        sensitive.append({
            "name": info.get("name") or act.get("user") or name,
            "display_name": info.get("display_name", ""),
            "description": info.get("description", ""),
            "roles": roles,
            "source": "ad" if info else "motif",
            "disabled": info.get("disabled", False),
            "password_never_expires": info.get("password_never_expires", False),
            "unconstrained_delegation": info.get("unconstrained_delegation", False),
            "spn_count": info.get("spn_count", 0),
            "password_set": info.get("password_set"),
            "ad_last_logon": info.get("last_logon"),
            "logons_7d": act.get("logons", 0),
            "failures_7d": act.get("failures", 0),
            "lockouts_7d": act.get("lockouts", 0),
            "hosts_7d": act.get("hosts", 0),
            "last_logon": _iso(act.get("last_logon")),
            "last_host": act.get("last_host", ""),
            "last_service": act.get("last_service", ""),
        })
    sensitive.sort(key=lambda a: (-(a["failures_7d"] + 10 * a["lockouts_7d"]), a["name"].lower()))
    return {
        "ad_configured": ad_configured(cfg),
        "ad_sync": bool(cfg.get("accounts_ad_sync", True)),
        "sync": await sync_status(state.redis),
        "patterns": {"admin": cfg.get("accounts_admin_patterns") or [],
                     "service": cfg.get("accounts_service_patterns") or []},
        "lockouts": await _lockouts(state.store, 24),
        "accounts": sensitive,
    }


@router.post("/api/admin/accounts/sync")
async def accounts_sync(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    cfg = await settings_store.load(db, force=True)
    if not ad_configured(cfg):
        raise HTTPException(409, "Compte de service LDAPS non configuré (Paramètres › Annuaire AD)")
    status = await sync_from_ad(request.app.state.redis, cfg)
    await audit.record(db, actor=user.username, ip=client_ip(request), action="accounts_sync", obj="ad",
                       detail={k: status[k] for k in ("admin", "service", "error")})
    await db.commit()
    return status
