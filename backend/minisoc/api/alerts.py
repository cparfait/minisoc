"""Consultation et traitement des alertes."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.deps import ANALYST, ANY_USER, client_ip, get_db
from minisoc.assets import INDEX as ASSETS
from minisoc.assets import AssetIndex, criticality_reasons
from minisoc.detections import CATEGORY_LABEL, priority, spread, tools_by_host
from minisoc.ecs import FIELDS, SEVERITY_BY_NAME, severity_name
from minisoc.followup import FollowupError, apply_update, deadlines, notify_assignee, overdue_filter
from minisoc.frameworks import describe
from minisoc.identity import same
from minisoc.models import ALERT_STATUSES, OPEN_STATUSES, Alert, AlertHistory, RuleException, User
from minisoc.response import ninja_tickets
from minisoc.rules.loader import load_playbook
from minisoc.settings_store import store as settings_store

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def entity_parts(entity_key: str) -> dict[str, str]:
    """« event.module=harfanglab | host.name=PC-01 | rule.name=… » → {"event.module": …, "host.name": …}."""
    parts = {}
    for part in (entity_key or "").split(" | "):
        field, sep, value = part.partition("=")
        if sep and value:
            parts[field.strip()] = value.strip()
    return parts


# Serveurs reconnus à leur nom (même règle que l'interface, components/Hosts.tsx)
SERVER_NAME = r"(srv|svr|serveur|dc|ad|fs|sql|web|app|mail|exch)[-_0-9]"
# Machine citée par l'alerte : entité, entités regroupées, événement déclencheur ou échantillon de postes
_HOST_AT = r'(host\.name=|"host\.name": "|"sample_hosts": \[([^]]*", )?")'
HAS_HOST = _HOST_AT + r'[^ |?"]'
HAS_SERVER = _HOST_AT + SERVER_NAME


_CITED_FIELDS = {
    "host": (r"host\.name", "sample_hosts"),
    "user": (r"user\.name", "sample_users"),
    "ip": (r"source\.ip", "sample_ips"),
}


def cites(kind: str, name: str) -> str:
    """Expression régulière (PostgreSQL) : l'alerte cite exactement cette machine (« host »), ce compte (« user ») ou
    cette adresse (« ip ») dans son entité, ses entités regroupées, son événement déclencheur ou ses échantillons —
    « PC-1 » ne correspond pas à « PC-10 ». S'applique à « entité + espace + détails JSON » : en fin d'entité, la valeur
    est suivie de « {" ; dans le JSON, une barre oblique inverse (DOMAINE\\compte) est doublée."""
    field, sample = _CITED_FIELDS[kind]
    name = name.strip()
    value = re.escape(name)
    encoded = re.escape(json.dumps(name, ensure_ascii=False)[1:-1])
    return (
        rf'({field}=({value}|{encoded})( \|| \{{|"|$)'
        rf'|"{field}": "{encoded}"|"{sample}": \[([^]]*", )?"{encoded}")'
    )


def impacted_hosts(alert: Alert) -> list[dict]:
    """Machines concernées : entité de l'alerte, entités regroupées (anti-tempête), événement déclencheur."""
    details = alert.details or {}
    hosts: dict[str, dict] = {}

    def add(name: str, count: int = 0, rule: str = "") -> None:
        name = (name or "").strip()
        if not name or name == "?":
            return
        entry = hosts.setdefault(name.lower(), {"name": name, "count": 0, "rules": []})
        entry["count"] += count
        if rule and rule not in entry["rules"]:
            entry["rules"].append(rule)

    own = entity_parts(alert.entity_key)
    add(own.get("host.name", ""), alert.count if own.get("host.name") else 0, own.get("rule.name", ""))
    for key, count in (details.get("entities") or {}).items():
        parts = entity_parts(key)
        add(parts.get("host.name", ""), int(count or 0), parts.get("rule.name", ""))
    sample = details.get("sample") or {}
    add(str(sample.get("host.name") or ""))
    for name in details.get("sample_hosts") or []:
        add(str(name))
    return sorted(hosts.values(), key=lambda h: (-h["count"], h["name"].lower()))


def serialize(
    alert: Alert, machines: dict | None = None, index: AssetIndex | None = None, cfg: dict | None = None,
    tools: dict | None = None,
) -> dict:
    """`machines` : nombre de machines par détection sur les alertes ouvertes (rareté, pour la priorité) ;
    `index` : inventaire (criticité, propriétaire, service des machines et comptes)."""
    qualification = (alert.details or {}).get("qualification") or {}
    hosts = impacted_hosts(alert)
    extra = []
    if index is not None:
        for host in hosts:
            info = index.host(host["name"])
            if info:
                host.update(
                    criticality=info.criticality, owner=info.owner, service=info.service, asset_type=info.asset_type
                )
        user = str(((alert.details or {}).get("sample") or {}).get("user.name") or "")
        extra = criticality_reasons(index, [h["name"] for h in hosts], user)
    score, reasons = priority(alert, machines or {}, [h["name"] for h in hosts], extra=extra, tools=tools)
    return {
        "hosts": hosts,
        "priority": score,
        "priority_reasons": reasons,
        "category": (alert.details or {}).get("category"),
        "verdict": qualification.get("verdict"),
        "verdict_label": qualification.get("label"),
        "id": alert.id,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "severity": severity_name(alert.severity),
        "title": alert.title,
        "entity_key": alert.entity_key,
        "status": alert.status,
        "assignee": alert.assignee,
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "count": alert.count,
        "metric": alert.metric,
        "modules": alert.modules,
        "reference": alert.reference,
        "incident_id": alert.incident_id,
        "source_closure": (alert.details or {}).get("source_closure"),  # clôturée dans l'outil d'origine
        "tool_state": (alert.details or {}).get("tool_state"),  # état lu dans l'outil d'origine (lecture seule)
        "ticket": (alert.details or {}).get("ninja_ticket"),  # ticket NinjaOne ouvert depuis l'alerte
        "waiting": (alert.details or {}).get("waiting"),
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "due": deadlines(alert, cfg) if cfg is not None else None,
        "notified_at": alert.notified_at.isoformat() if alert.notified_at else None,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }


async def _open_light(db: AsyncSession) -> list[Alert]:
    """Alertes ouvertes, colonnes utiles seulement (rareté des détections, outils ayant signalé chaque machine)."""
    rows = await db.execute(
        select(Alert.entity_key, Alert.modules, Alert.count, Alert.details["entities"], Alert.details["storm"],
               Alert.details["category"], Alert.details["sample"]).where(Alert.status.in_(OPEN_STATUSES))
    )
    return [
        Alert(entity_key=key, modules=modules, count=count,
              details={"entities": entities or {}, "storm": bool(storm), "category": category,
                       "sample": {"host.name": (sample or {}).get("host.name", "")}})
        for key, modules, count, entities, storm, category, sample in rows.all()
    ]


async def machines_by_detection(db: AsyncSession) -> dict:
    """Nombre de machines par détection sur les alertes ouvertes."""
    return spread(await _open_light(db))


OPEN_CONTEXT_SECONDS = 10
_open_context_cache: tuple[float, tuple[dict, dict]] | None = None


async def open_context(db: AsyncSession) -> tuple[dict, dict]:
    """(machines par détection, outils de détection ayant signalé chaque machine) sur les alertes ouvertes.
    Gardé quelques secondes : il sert à chaque requête d'alertes, et ces nombres n'orientent que la priorité."""
    global _open_context_cache
    now = time.monotonic()
    if _open_context_cache and _open_context_cache[0] > now:
        return _open_context_cache[1]
    light = await _open_light(db)
    context = spread(light), tools_by_host(light)
    _open_context_cache = (now + OPEN_CONTEXT_SECONDS, context)
    return context


SORTS = {
    "recent": (Alert.last_seen.desc(),),
    "severity": (Alert.severity.desc(), Alert.last_seen.desc()),
    "oldest": (Alert.first_seen.asc(),),
    "count": (Alert.count.desc(), Alert.last_seen.desc()),
}


def _aware(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


@router.get("")
async def list_alerts(
    status: str | None = Query(None, description="statuts séparés par des virgules"),
    severity_min: str | None = None,
    rule_id: str | None = None,
    module: str | None = Query(None, max_length=64),
    verdict: str | None = Query(None, max_length=32),
    assignee: str | None = Query(None, max_length=64, description="« me », « none » ou un identifiant"),
    since: datetime | None = Query(None, description="activité de l'alerte à partir de (ISO 8601)"),
    until: datetime | None = Query(None, description="activité de l'alerte jusqu'à (ISO 8601)"),
    q: str | None = Query(None, max_length=200),
    host_kind: str | None = Query(None, pattern="^(server|workstation)$", description="serveurs ou postes de travail"),
    detection: str | None = Query(None, max_length=256, description="nom exact de la détection de l'outil"),
    category: str | None = Query(None, pattern="^(threat|hygiene|info)$"),
    host: str | None = Query(None, max_length=256, description="alertes citant cette machine (nom exact)"),
    overdue: bool = Query(False, description="seulement les alertes en retard sur leur échéance"),
    ticket: str | None = Query(None, pattern="^open$", description="alertes avec un ticket NinjaOne ouvert"),
    account: str | None = Query(None, max_length=256, description="alertes citant ce compte (nom exact)"),
    ip: str | None = Query(None, max_length=64, description="alertes citant cette adresse IP source (adresse exacte)"),
    sort: str = Query("recent"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(ANY_USER),
):
    """Alertes filtrées. Période : alertes actives pendant la période (première détection avant la fin, dernière
    détection après le début). `by_status` : effectifs par statut avec les mêmes filtres (hors statut)."""
    filters = []
    if severity_min in SEVERITY_BY_NAME:
        filters.append(Alert.severity >= SEVERITY_BY_NAME[severity_min])
    if rule_id:
        filters.append(Alert.rule_id == rule_id)
    if module:
        filters.append(Alert.modules.contains([module]))
    if verdict:
        filters.append(Alert.details["qualification"]["verdict"].astext == verdict)
    if assignee == "me":
        filters.append(Alert.assignee == user.username)
    elif assignee == "none":
        filters.append(Alert.assignee.is_(None))
    elif assignee:
        filters.append(Alert.assignee == assignee)
    if since is not None:
        filters.append(Alert.last_seen >= _aware(since))
    if until is not None:
        filters.append(Alert.first_seen <= _aware(until))
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        filters.append(
            Alert.title.ilike(pattern)
            | Alert.entity_key.ilike(pattern)
            | Alert.rule_name.ilike(pattern)
            | cast(Alert.details["entities"], String).ilike(pattern)
        )  # postes d'un regroupement
    if host_kind:
        text = Alert.entity_key + " " + cast(Alert.details, String)
        server = text.op("~*")(HAS_SERVER)
        filters.append(server if host_kind == "server" else text.op("~*")(HAS_HOST) & ~server)
    cfg = await settings_store.load(db)
    if overdue:
        filters.append(overdue_filter(cfg))
    if ticket:
        filters.append(ninja_tickets.open_filter())
    if host:
        filters.append((Alert.entity_key + " " + cast(Alert.details, String)).op("~*")(cites("host", host)))
    if account:
        filters.append((Alert.entity_key + " " + cast(Alert.details, String)).op("~*")(cites("user", account)))
    if ip:
        filters.append((Alert.entity_key + " " + cast(Alert.details, String)).op("~*")(cites("ip", ip)))
    if detection:
        escaped = detection.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        # Entité terminée par la détection, ou entité d'un regroupement (clé JSON suivie d'un guillemet)
        filters.append(
            Alert.entity_key.ilike(f"%rule.name={escaped}")
            | cast(Alert.details["entities"], String).ilike(f'%rule.name={escaped}"%')
        )
    if category == "threat":
        filters.append(Alert.details["category"].astext.is_(None) | (Alert.details["category"].astext == "threat"))
    elif category:
        filters.append(Alert.details["category"].astext == category)
    stmt = select(Alert).where(*filters)
    counts = await db.execute(select(Alert.status, func.count()).where(*filters).group_by(Alert.status))
    by_status = dict(counts.all())
    if status:
        statuses = [s for s in status.split(",") if s in ALERT_STATUSES]
        stmt = stmt.where(Alert.status.in_(statuses))
    total = await db.scalar(select(func.count()).select_from(stmt.subquery()))
    machines, tools = await open_context(db)
    index = await ASSETS.ensure(db)
    if sort == "priority":  # score calculé : tri en mémoire (quelques milliers d'alertes au plus)
        items = [serialize(a, machines, index, cfg, tools) for a in (await db.scalars(stmt)).all()]
        items.sort(key=lambda a: a["last_seen"], reverse=True)
        items.sort(key=lambda a: a["priority"], reverse=True)  # tri stable : à score égal, la plus récente
        return {"total": total, "by_status": by_status, "items": items[offset : offset + limit]}
    rows = await db.scalars(stmt.order_by(*SORTS.get(sort, SORTS["recent"])).limit(limit).offset(offset))
    items = [serialize(a, machines, index, cfg, tools) for a in rows.all()]
    return {"total": total, "by_status": by_status, "items": items}


RELATED_PER_KIND = 3
RELATED_LIMIT = 30


def related_lookups(hosts: list[str], accounts: list[str], ips: list[str]) -> list[tuple[str, str]]:
    """(expression régulière, libellé) de chaque valeur recherchée, les premières de chaque type."""
    wanted = (("host", "machine", hosts), ("user", "compte", accounts), ("ip", "IP", ips))
    return [
        (cites(kind, value), f"{label} {value.strip()}")
        for kind, label, values in wanted
        for value in [v for v in values if v.strip()][:RELATED_PER_KIND]
    ]


def related_labels(alert: Alert, lookups: list[tuple[str, str]]) -> list[str]:
    """Valeurs recherchées que cite l'alerte, sur le même texte que le filtre SQL (JSONB : mêmes espaces)."""
    text = f"{alert.entity_key} {json.dumps(alert.details or {}, ensure_ascii=False)}"
    return [label for pattern, label in lookups if re.search(pattern, text, re.IGNORECASE)]


@router.get("/related")
async def related_alerts(
    host: list[str] = Query([]),
    account: list[str] = Query([]),
    ip: list[str] = Query([]),
    exclude: int | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    """Alertes ouvertes citant ces machines, comptes ou IP, en une seule requête. Les plus récentes à la lecture,
    puis les plus liées et les plus prioritaires à l'affichage. `truncated` : d'autres alertes existent au-delà."""
    lookups = related_lookups(host, account, ip)
    if not lookups:
        return {"items": [], "truncated": False}
    stmt = select(Alert).where(
        Alert.status.in_(OPEN_STATUSES),
        (Alert.entity_key + " " + cast(Alert.details, String)).op("~*")("|".join(p for p, _label in lookups)),
    )
    if exclude is not None:
        stmt = stmt.where(Alert.id != exclude)
    rows = (await db.scalars(stmt.order_by(Alert.last_seen.desc()).limit(RELATED_LIMIT + 1))).all()
    machines, tools = await open_context(db)
    index = await ASSETS.ensure(db)
    cfg = await settings_store.load(db)
    items = [
        {**serialize(a, machines, index, cfg, tools), "via": related_labels(a, lookups)} for a in rows[:RELATED_LIMIT]
    ]
    items.sort(key=lambda a: (-len(a["via"]), -a["priority"]))
    return {"items": items, "truncated": len(rows) > RELATED_LIMIT}


@router.get("/facets")
async def alert_facets(db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    """Valeurs proposées dans les filtres : sources, règles et personnes assignées présentes dans les alertes."""
    modules = await db.scalars(select(func.jsonb_array_elements_text(Alert.modules)).distinct())
    rules = await db.execute(
        select(Alert.rule_id, func.max(Alert.rule_name)).group_by(Alert.rule_id).order_by(Alert.rule_id)
    )
    assignees = await db.scalars(select(Alert.assignee).where(Alert.assignee.is_not(None)).distinct())
    return {
        "modules": sorted(modules.all()),
        "rules": [{"id": r, "name": n} for r, n in rules.all()],
        "assignees": sorted(assignees.all()),
        "tickets": ninja_tickets.enabled(await settings_store.load(db)),  # filtre proposé si la fonction est active
    }


@router.get("/assignees")
async def assignees(db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    """Personnes à qui une alerte peut être assignée."""
    rows = await db.scalars(
        select(User).where(User.active.is_(True), User.role.in_(("admin", "analyst"))).order_by(User.username)
    )
    return {
        "items": [
            {"username": u.username, "display_name": u.display_name or u.username, "has_email": bool(u.email)}
            for u in rows.all()
        ]
    }


FP_WINDOW_DAYS = 90
FP_SUGGEST_FROM = 2  # clôtures en faux positif avant de proposer une exception


def exception_target(entity_key: str) -> tuple[str, str] | None:
    """Champ et valeur qu'une exception couvrirait : la détection de l'outil si l'entité en cite une (une exception sur
    la machine ferait taire toutes les détections de ce poste), sinon le dernier élément de l'entité."""
    parts = {f: v for f, v in entity_parts(entity_key).items() if f in FIELDS and f != "event.module"}
    if "rule.name" in parts:
        return "rule.name", parts["rule.name"]
    return next(reversed(parts.items()), None)


def closed_as_false_positive(alert_id: int, rule_id: str, entity_key: str, field: str, value: str, since: datetime):
    """Autres alertes de cette règle jugées faux positif : même détection sur toute machine, sinon même entité."""
    same_target = (
        Alert.entity_key.endswith(f"rule.name={value}", autoescape=True)
        if field == "rule.name"
        else Alert.entity_key == entity_key
    )
    return (
        Alert.rule_id == rule_id, Alert.status == "false_positive", Alert.id != alert_id, Alert.updated_at >= since,
        same_target,
    )


async def exception_hint(db: AsyncSession, alert: Alert) -> dict | None:
    """Proposition d'exception : alerte ouverte, déjà jugée plusieurs fois faux positif, et rien ne la couvre encore."""
    target = exception_target(alert.entity_key) if alert.status in OPEN_STATUSES else None
    if target is None:
        return None
    field, value = target
    now = datetime.now(timezone.utc)
    where = closed_as_false_positive(alert.id, alert.rule_id, alert.entity_key, field, value,
                                     now - timedelta(days=FP_WINDOW_DAYS))
    count, last_at = (await db.execute(select(func.count(), func.max(Alert.updated_at)).where(*where))).one()
    if count < FP_SUGGEST_FROM:
        return None
    active = await db.scalars(
        select(RuleException).where(
            RuleException.rule_id.in_((alert.rule_id, "*")), RuleException.field == field,
            RuleException.expires_at > now,
        )
    )
    if any(same(field, value, e.value) for e in active.all()):
        return None
    comment = await db.scalar(
        select(AlertHistory.detail)
        .join(Alert, AlertHistory.alert_id == Alert.id)
        .where(*where, AlertHistory.action == "comment")
        .order_by(AlertHistory.ts.desc())
        .limit(1)
    )
    return {"count": count, "days": FP_WINDOW_DAYS, "field": field, "value": value,
            "last_at": last_at.isoformat() if last_at else None, "last_comment": comment or ""}


@router.get("/{alert_id}")
async def get_alert(alert_id: int, request: Request, db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alerte introuvable")
    history = await db.scalars(select(AlertHistory).where(AlertHistory.alert_id == alert_id).order_by(AlertHistory.ts))
    state = request.app.state
    rule = state.rules.by_id.get(alert.rule_id)
    try:
        events = await state.store.by_ids(alert.event_ids)
    except Exception:  # noqa: BLE001 - l'alerte reste consultable si ClickHouse est indisponible
        events = []
    machines, tools = await open_context(db)
    return {
        **serialize(alert, machines, await ASSETS.ensure(db), await settings_store.load(db), tools),
        "category_label": CATEGORY_LABEL.get((alert.details or {}).get("category") or "threat"),
        "exception_hint": await exception_hint(db, alert),
        "details": alert.details,
        "rule": {
            "description": rule.description if rule else "",
            "type": rule.type if rule else "",
            "mitre": [describe(t) for t in rule.mitre] if rule else [],
        },
        "playbook": load_playbook(state.settings.rules_dir, rule) if rule else "",
        "history": [
            {"ts": h.ts.isoformat(), "actor": h.actor, "action": h.action, "detail": h.detail} for h in history.all()
        ],
        "events": [_event(e) for e in events],
    }


@router.post("/{alert_id}/ungroup")
async def ungroup_alert(
    alert_id: int, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ANALYST)
):
    """Alerte de regroupement (anti-tempête) → une alerte par entité, sans nouvelle notification."""
    from minisoc.ungroup import UngroupError, ungroup

    try:
        created = await ungroup(db, request.app.state.store, request.app.state.rules, alert_id, user.username)
    except UngroupError as exc:
        raise HTTPException(422, str(exc)) from None
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="alert_ungroup",
        obj=f"alert:{alert_id}",
        detail={"created": created},
    )
    await db.commit()
    return {"created": created}


class AlertUpdate(BaseModel):
    status: str | None = None
    assignee: str | None = Field(None, max_length=64)
    waiting_reason: str | None = Field(None, max_length=32)
    comment: str | None = Field(None, max_length=4000)


async def _assignee(db: AsyncSession, username: str | None) -> User | None:
    """Personne assignable : analyste ou administrateur actif."""
    if not username:
        return None
    target = await db.scalar(select(User).where(User.username == username.strip().lower()))
    if target is None or not target.active or target.role not in ("admin", "analyst"):
        raise HTTPException(422, f"« {username} » n'est pas un analyste ou administrateur actif")
    return target


@router.patch("/{alert_id}")
async def update_alert(
    alert_id: int,
    body: AlertUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(ANALYST),
):
    alert = await db.get(Alert, alert_id, with_for_update=True)
    if not alert:
        raise HTTPException(404, "Alerte introuvable")
    assign = "assignee" in body.model_fields_set
    target = await _assignee(db, body.assignee) if assign else None
    try:
        changes = apply_update(
            db,
            alert,
            user.username,
            status=body.status,
            assignee=target.username if target else None,
            assign=assign,
            waiting_reason=body.waiting_reason,
            comment=body.comment,
        )
    except FollowupError as exc:
        raise HTTPException(422, str(exc)) from None
    if changes:
        await audit.record(
            db,
            actor=user.username,
            ip=client_ip(request),
            action="alert_update",
            obj=f"alert:{alert.id}",
            detail=changes,
        )
        await db.commit()
        if "assignee" in changes and target:
            cfg = await settings_store.load(db)
            await notify_assignee(cfg, target, [alert], user.username, request.app.state.settings.public_url)
    return serialize(alert, cfg=await settings_store.load(db))


class BulkUpdate(BaseModel):
    alert_ids: list[int] = Field(min_length=1, max_length=500)
    status: str | None = None
    assignee: str | None = Field(None, max_length=64)
    assign: bool = False  # True : appliquer `assignee` (vide = retirer l'assignation)
    waiting_reason: str | None = Field(None, max_length=32)
    comment: str | None = Field(None, max_length=4000)


@router.post("/bulk")
async def bulk_update(
    body: BulkUpdate, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ANALYST)
):
    """Même mise à jour sur une sélection d'alertes (assignation, prise en charge, mise en attente, clôture)."""
    target = await _assignee(db, body.assignee) if body.assign else None
    alerts = (await db.scalars(select(Alert).where(Alert.id.in_(body.alert_ids)).with_for_update())).all()
    changed = []
    try:
        for alert in alerts:
            if apply_update(
                db,
                alert,
                user.username,
                status=body.status,
                assignee=target.username if target else None,
                assign=body.assign,
                waiting_reason=body.waiting_reason,
                comment=body.comment,
            ):
                changed.append(alert)
    except FollowupError as exc:
        await db.rollback()
        raise HTTPException(422, str(exc)) from None
    if changed:
        await audit.record(
            db,
            actor=user.username,
            ip=client_ip(request),
            action="alert_bulk_update",
            obj="alerts",
            detail={
                "alerts": [a.id for a in changed],
                "status": body.status,
                "assignee": target.username if target else (None if body.assign else "inchangé"),
            },
        )
        await db.commit()
        if body.assign and target:
            cfg = await settings_store.load(db)
            await notify_assignee(cfg, target, changed, user.username, request.app.state.settings.public_url)
    return {"updated": len(changed)}


def _event(row: dict) -> dict:
    out = {}
    for key, value in row.items():
        if isinstance(value, datetime):
            # ClickHouse renvoie des dates UTC sans fuseau : sans « +00:00 », le navigateur les lirait en heure locale
            value = (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()
        elif hasattr(value, "isoformat"):
            value = value.isoformat()
        elif not isinstance(value, (str, int, float, bool, type(None))):
            value = str(value)
        out[key] = value
    return out
