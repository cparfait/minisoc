"""Assistant IA : analyse d'une alerte et questions libres, réponses diffusées en continu (SSE).

Garde-fous : clé et fournisseur côté serveur, données pseudonymisées (si activé), contenu des journaux
transmis comme données non fiables, aucune action possible par l'IA, usage limité et journalisé.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.ai import catalog
from minisoc.ai.context import alert_context, event_context, situation_context
from minisoc.ai.prompts import SYSTEM
from minisoc.ai.providers import AIError, StreamResult, configured, is_local, list_models, model, provider, stream_chat
from minisoc.ai.pseudonymize import Pseudonymizer, StreamRestorer
from minisoc.api.data import sources_status
from minisoc.api.deps import ADMIN, ANALYST, ANY_USER, client_ip, get_db
from minisoc.db import sessionmaker
from minisoc.models import Alert, User
from minisoc.rules.loader import load_playbook
from minisoc.settings_store import store as settings_store

router = APIRouter(prefix="/api/ai", tags=["ai"])

MAX_TURNS = 20
MAX_CHARS = 4000
RATE_WINDOW = 3600
RATE_MAX = 40
_usage: dict[str, deque[float]] = defaultdict(deque)


class Turn(BaseModel):
    role: str
    content: str = Field(max_length=MAX_CHARS * 4)

    @field_validator("role")
    @classmethod
    def _role(cls, value: str) -> str:
        if value not in ("user", "assistant"):
            raise ValueError("rôle user ou assistant attendu")
        return value


class Conversation(BaseModel):
    messages: list[Turn] = Field(default_factory=list, max_length=MAX_TURNS)


@router.get("/status")
async def ai_status(db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    cfg = await settings_store.load(db)
    p = provider(cfg)
    return {"enabled": configured(cfg), "provider": p.id, "label": p.name, "model": model(cfg),
            "pseudonymize": bool(cfg.get("ai_pseudonymize")), "local": is_local(cfg)}


def _rate_limit(user: User) -> None:
    now = time.monotonic()
    calls = _usage[user.username]
    while calls and now - calls[0] > RATE_WINDOW:
        calls.popleft()
    if len(calls) >= RATE_MAX:
        raise HTTPException(429, f"Limite de {RATE_MAX} demandes à l'IA par heure atteinte")
    calls.append(now)


def _build_messages(context: str, default_question: str, turns: list[Turn], pseudo: Pseudonymizer) -> list[dict]:
    """1er message = contexte + question ; tours suivants : historique renvoyé par le navigateur (pseudonymisé)."""
    if turns and turns[-1].role != "user":
        raise HTTPException(422, "La conversation doit se terminer par une question")
    first_question = turns[0].content if turns and turns[0].role == "user" else default_question
    messages = [{"role": "user", "content": f"{context}\n\n{pseudo.text(first_question[:MAX_CHARS])}"}]
    rest = turns[1:] if turns and turns[0].role == "user" else turns
    for turn in rest:
        messages.append({"role": turn.role, "content": pseudo.text(turn.content[:MAX_CHARS * 4])})
    return messages


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


async def _stream(cfg: dict, messages: list[dict], pseudo: Pseudonymizer, user: User, ip: str,
                  obj: str) -> AsyncIterator[str]:
    result = StreamResult()
    restorer = StreamRestorer(pseudo)
    error = ""
    yield _sse({"type": "start", "pseudonymized": pseudo.enabled, "provider": cfg.get("ai_provider")})
    try:
        async for chunk in stream_chat(cfg, SYSTEM, messages, result):
            text = restorer.feed(chunk)
            if text:
                yield _sse({"type": "text", "text": text})
        tail = restorer.flush()
        if tail:
            yield _sse({"type": "text", "text": tail})
        for notice in result.notices:
            yield _sse({"type": "notice", "text": notice})
        yield _sse({"type": "done", "model": result.model, "input_tokens": result.input_tokens,
                    "output_tokens": result.output_tokens})
    except AIError as exc:
        error = str(exc)
        yield _sse({"type": "error", "message": error})
    finally:
        # Traçabilité : qui a envoyé quoi (identifiant d'objet, jamais le contenu) à quel fournisseur
        async with sessionmaker()() as db:
            await audit.record(db, actor=user.username, ip=ip, action="ai_request", obj=obj, detail={
                "provider": cfg.get("ai_provider"), "model": result.model or cfg.get("ai_model"),
                "pseudonymized": pseudo.enabled, "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens, "error": error or None,
            })
            await db.commit()


def _response(generator: AsyncIterator[str]) -> StreamingResponse:
    return StreamingResponse(generator, media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


async def _ready_cfg(db: AsyncSession, user: User) -> dict:
    cfg = await settings_store.load(db)
    if not configured(cfg):
        raise HTTPException(409, "Assistant IA non configuré (Paramètres > Assistant IA)")
    _rate_limit(user)
    return cfg


@router.post("/alerts/{alert_id}/analyze")
async def analyze_alert(alert_id: int, body: Conversation, request: Request, db: AsyncSession = Depends(get_db),
                        user: User = Depends(ANALYST)):
    cfg = await _ready_cfg(db, user)
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alerte introuvable")
    state = request.app.state
    rule = state.rules.by_id.get(alert.rule_id)
    pseudo = Pseudonymizer(enabled=bool(cfg.get("ai_pseudonymize")) and not is_local(cfg))
    playbook = load_playbook(state.settings.rules_dir, rule) if rule else ""
    context = await alert_context(alert, state.rules, state.store, db, pseudo, playbook)
    messages = _build_messages(context, "Analyse cette alerte.", body.messages, pseudo)
    return _response(_stream(cfg, messages, pseudo, user, client_ip(request), f"alert:{alert_id}"))


@router.post("/events/{event_id}/analyze")
async def analyze_event(event_id: str, body: Conversation, request: Request, db: AsyncSession = Depends(get_db),
                        user: User = Depends(ANALYST)):
    """Analyse d'un événement isolé (liste des événements, détail d'une alerte)."""
    cfg = await _ready_cfg(db, user)
    state = request.app.state
    events = await state.store.by_ids([event_id], limit=1)
    if not events:
        raise HTTPException(404, "Événement introuvable")
    pseudo = Pseudonymizer(enabled=bool(cfg.get("ai_pseudonymize")) and not is_local(cfg))
    context = await event_context(events[0], state.store, db, pseudo)
    question = ("Analyse cet événement : que s'est-il passé, est-ce plausiblement légitime ou malveillant, "
                "quelles vérifications concrètes faire et quelle action recommandes-tu ?")
    messages = _build_messages(context, question, body.messages, pseudo)
    return _response(_stream(cfg, messages, pseudo, user, client_ip(request), f"event:{event_id}"))


@router.post("/chat")
async def chat(body: Conversation, request: Request, db: AsyncSession = Depends(get_db),
               user: User = Depends(ANALYST)):
    if not body.messages:
        raise HTTPException(422, "Question manquante")
    cfg = await _ready_cfg(db, user)
    state = request.app.state
    pseudo = Pseudonymizer(enabled=bool(cfg.get("ai_pseudonymize")) and not is_local(cfg))
    context = await situation_context(db, state.store, await sources_status(state), pseudo)
    messages = _build_messages(context, "", body.messages, pseudo)
    return _response(_stream(cfg, messages, pseudo, user, client_ip(request), "chat"))


@router.post("/test")
async def test_ai(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    """Vérifie la configuration avec une demande minimale (bouton « Tester » des paramètres)."""
    cfg = await _ready_cfg(db, user)
    result = StreamResult()
    text = ""
    try:
        async for chunk in stream_chat({**cfg, "ai_max_tokens": 256}, "Réponds uniquement par le mot OK.",
                                       [{"role": "user", "content": "Test de connexion."}], result):
            text += chunk
    except AIError as exc:
        return {"ok": False, "detail": str(exc)}
    return {"ok": True, "detail": f"Réponse de {result.model or cfg.get('ai_model')} : {text.strip()[:80]}"}


# --- Gestion des fournisseurs (reprise du panneau « Fournisseurs d'IA » de LMU Stats Viewer) ------------------------

class ProviderKey(BaseModel):
    key: str = Field("", max_length=4000)


class CustomProvider(BaseModel):
    name: str = Field("", max_length=80)
    base_url: str = Field(min_length=8, max_length=500)
    key: str | None = Field(None, max_length=4000)


async def _save(db: AsyncSession, request: Request, user: User, changes: dict, action: str, obj: str) -> None:
    from minisoc.settings_store import SettingsError

    try:
        await settings_store.update_keys(db, set(changes), changes, user.username)
    except SettingsError as exc:
        raise HTTPException(422, str(exc)) from None
    await audit.record(db, actor=user.username, ip=client_ip(request), action=action, obj=obj)
    await db.commit()


@router.get("/providers")
async def providers_list(db: AsyncSession = Depends(get_db), _: User = Depends(ADMIN)):
    cfg = await settings_store.load(db, force=True)
    return {"active": provider(cfg).id, "model": cfg.get("ai_model") or "", "providers": catalog.public_list(cfg)}


@router.put("/providers/{provider_id}/key")
async def provider_set_key(provider_id: str, body: ProviderKey, request: Request, db: AsyncSession = Depends(get_db),
                           user: User = Depends(ADMIN)):
    cfg = await settings_store.load(db, force=True)
    if provider_id not in catalog.all_providers(cfg):
        raise HTTPException(404, "Fournisseur inconnu")
    keys = catalog.provider_keys(cfg)
    if body.key.strip():
        keys[provider_id] = body.key.strip()
    else:
        keys.pop(provider_id, None)
    await _save(db, request, user, {"ai_provider_keys": json.dumps(keys)}, "ai_provider_key",
                f"ai_provider:{provider_id}")
    return {"key_set": bool(body.key.strip())}


def _check_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(422, "Adresse http(s):// attendue (racine de l'API compatible OpenAI, ex. …/v1)")
    return url


@router.post("/custom-providers", status_code=201)
async def custom_add(body: CustomProvider, request: Request, db: AsyncSession = Depends(get_db),
                     user: User = Depends(ADMIN)):
    cfg = await settings_store.load(db, force=True)
    defs = [d.__dict__ for d in catalog.custom_defs(cfg)]
    new_id = catalog.new_custom_id()
    url = _check_url(body.base_url)
    defs.append({"id": new_id, "name": body.name.strip() or url, "base_url": url})
    changes = {"ai_custom_providers": json.dumps(defs)}
    if body.key:
        changes["ai_provider_keys"] = json.dumps({**catalog.provider_keys(cfg), new_id: body.key.strip()})
    await _save(db, request, user, changes, "ai_custom_provider_add", f"ai_provider:{new_id}")
    return {"id": new_id}


@router.put("/custom-providers/{provider_id}")
async def custom_update(provider_id: str, body: CustomProvider, request: Request, db: AsyncSession = Depends(get_db),
                        user: User = Depends(ADMIN)):
    cfg = await settings_store.load(db, force=True)
    defs = [d.__dict__ for d in catalog.custom_defs(cfg)]
    target = next((d for d in defs if d["id"] == provider_id), None)
    if target is None:
        raise HTTPException(404, "Fournisseur personnalisé inconnu")
    target["base_url"] = _check_url(body.base_url)
    target["name"] = body.name.strip() or target["base_url"]
    changes = {"ai_custom_providers": json.dumps(defs)}
    if body.key is not None and body.key.strip():
        changes["ai_provider_keys"] = json.dumps({**catalog.provider_keys(cfg), provider_id: body.key.strip()})
    await _save(db, request, user, changes, "ai_custom_provider_update", f"ai_provider:{provider_id}")
    return {"id": provider_id}


@router.delete("/custom-providers/{provider_id}")
async def custom_delete(provider_id: str, request: Request, db: AsyncSession = Depends(get_db),
                        user: User = Depends(ADMIN)):
    cfg = await settings_store.load(db, force=True)
    defs = [d.__dict__ for d in catalog.custom_defs(cfg) if d.id != provider_id]
    keys = {k: v for k, v in catalog.provider_keys(cfg).items() if k != provider_id}
    changes = {"ai_custom_providers": json.dumps(defs), "ai_provider_keys": json.dumps(keys)}
    if cfg.get("ai_provider") == provider_id:
        changes.update({"ai_provider": "anthropic", "ai_model": ""})
    await _save(db, request, user, changes, "ai_custom_provider_delete", f"ai_provider:{provider_id}")
    return {"deleted": provider_id}


@router.get("/providers/{provider_id}/models")
async def provider_models(provider_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(ADMIN)):
    """Modèles disponibles chez le fournisseur (lus avec sa clé), ou liste de repli avec l'explication."""
    cfg = await settings_store.load(db, force=True)
    if provider_id not in catalog.all_providers(cfg):
        raise HTTPException(404, "Fournisseur inconnu")
    models, warning = await list_models(cfg, provider_id)
    return {"models": models, "warning": warning, "docs_url": catalog.provider(cfg, provider_id).docs_url}
