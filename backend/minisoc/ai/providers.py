"""Appels aux fournisseurs d'IA (reprise du connecteur de LMU Stats Viewer, côté serveur, en flux).

La clé et l'adresse restent côté serveur ; le navigateur ne reçoit que le texte produit. Particularités reprises de
LMU (`src/lib/ai/providers/*.ts`) :
  - marge de 1 024 jetons pour la réflexion des modèles (sinon réponse vide sur les modèles « thinking ») ;
  - OpenAI : `max_completion_tokens` (les modèles de raisonnement refusent `max_tokens`) ;
  - erreurs signalées DANS un flux HTTP 200 (passerelles, surcharge) et fins anticipées (plafond, filtre) remontées ;
  - tours vides retirés (Anthropic refuse un message vide) ;
  - Google : clé dans l'en-tête `x-goog-api-key` (jamais dans l'URL, qui finit dans les messages d'erreur),
    `systemInstruction`, rôle « model » ;
  - liste des modèles lue chez le fournisseur, filtrée et triée par récence, avec repli statique.
Claude passe par le SDK officiel Anthropic (repli automatique du serveur en cas de refus de sécurité).
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import anthropic
import httpx

from minisoc.ai.catalog import (  # noqa: F401 (réexportés pour le reste de l'application)
    BUILTIN,
    NON_CHAT,
    THINKING_HEADROOM,
    Provider,
    all_providers,
    api_key,
    base_url,
    configured,
    is_local,
    model,
    provider,
)

DEFAULT_MODELS = {p.id: p.default_model for p in BUILTIN.values() if p.default_model}


class AIError(RuntimeError):
    pass


@dataclass
class StreamResult:
    model: str = ""
    stop_reason: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    notices: list[str] = field(default_factory=list)


STOP_NOTICES = {
    "max_tokens": "Réponse tronquée (limite de longueur atteinte).",
    "length": "Réponse tronquée (limite de longueur atteinte).",
    "MAX_TOKENS": "Réponse tronquée (limite de longueur atteinte).",
    "content_filter": "Réponse interrompue par le filtre de contenu du fournisseur.",
    "SAFETY": "Réponse interrompue par le filtre de sécurité de Google.",
    "refusal": "Le modèle a décliné cette demande (filtre de sécurité).",
}


def _non_empty(messages: list[dict]) -> list[dict]:
    return [m for m in messages if str(m.get("content", "")).strip()]


def _http_error(name: str, status: int, model_id: str, detail: str) -> str:
    if status in (401, 403):
        return f"{name} : clé d'API refusée ou sans droits (HTTP {status})"
    if status == 404:
        return f"{name} : modèle « {model_id} » ou adresse introuvable (HTTP 404)"
    if status == 429:
        return f"{name} : limite de débit ou de crédit atteinte (HTTP 429), réessayer plus tard"
    if status in (500, 502, 503, 529):
        return f"{name} : service surchargé ou indisponible (HTTP {status}), réessayer plus tard"
    return f"{name} : erreur HTTP {status} : {detail[:200]}"


async def stream_chat(cfg: dict, system: str, messages: list[dict], result: StreamResult) -> AsyncIterator[str]:
    p = provider(cfg)
    runner = {"anthropic": _anthropic, "google": _google, "ollama": _ollama}.get(p.kind, _openai_compatible)
    async for chunk in runner(cfg, p, system, _non_empty(messages), result):
        yield chunk
    notice = STOP_NOTICES.get(result.stop_reason)
    if notice and notice not in result.notices:
        result.notices.append(notice)


# --- Anthropic (SDK officiel) -------------------------------------------------------------------------------------

async def _anthropic(cfg: dict, p: Provider, system: str, messages: list[dict],
                     result: StreamResult) -> AsyncIterator[str]:
    client = anthropic.AsyncAnthropic(api_key=api_key(cfg), timeout=120.0, max_retries=2)
    model_id = model(cfg)
    try:
        async with client.beta.messages.stream(
            model=model_id,
            max_tokens=int(cfg.get("ai_max_tokens") or 16000),
            system=system,
            messages=messages,
            cache_control={"type": "ephemeral"},
            output_config={"effort": cfg.get("ai_effort") or "medium"},
            # Repli côté serveur si les filtres de sécurité du modèle déclinent la demande : l'analyse de
            # journaux d'attaque peut ressembler à du contenu « cyber » sensible
            betas=["server-side-fallback-2026-07-01"],
            extra_body={"fallbacks": "default"},
        ) as stream:
            async for text in stream.text_stream:
                yield text
            final = await stream.get_final_message()
    except anthropic.AuthenticationError:
        raise AIError("Clé d'API Anthropic refusée : vérifier la clé du fournisseur") from None
    except anthropic.PermissionDeniedError:
        raise AIError("Clé d'API sans droits suffisants pour ce modèle") from None
    except anthropic.NotFoundError:
        raise AIError(f"Modèle inconnu : {model_id}") from None
    except anthropic.RateLimitError:
        raise AIError("Limite de débit atteinte chez Anthropic : réessayer dans une minute") from None
    except anthropic.APIStatusError as exc:
        raise AIError(f"Erreur du service d'IA (HTTP {exc.status_code})") from None
    except anthropic.APIConnectionError:
        raise AIError("Service d'IA injoignable : vérifier l'accès Internet sortant vers api.anthropic.com") from None
    finally:
        await client.close()

    result.model = final.model
    result.stop_reason = final.stop_reason or ""
    result.input_tokens = final.usage.input_tokens
    result.output_tokens = final.usage.output_tokens
    if any(getattr(block, "type", "") == "fallback" for block in final.content):
        result.notices.append(f"Réponse produite par le modèle de repli {final.model}.")


# --- Compatible OpenAI (OpenAI, OpenRouter, DeepSeek, Mistral, fournisseurs personnalisés) ------------------------

async def _openai_compatible(cfg: dict, p: Provider, system: str, messages: list[dict],
                             result: StreamResult) -> AsyncIterator[str]:
    model_id = model(cfg)
    key = api_key(cfg)
    headers = {"Content-Type": "application/json"}
    if key:  # LMU custom.ts : beaucoup de serveurs locaux n'exigent pas de clé
        headers["Authorization"] = f"Bearer {key}"
    body = {"model": model_id, "messages": [{"role": "system", "content": system}, *messages], "stream": True,
            p.max_tokens_field: int(cfg.get("ai_max_tokens") or 4000) + THINKING_HEADROOM}
    async for line in _sse(p, f"{base_url(cfg)}/chat/completions", headers, body, model_id):
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            break
        try:
            chunk = json.loads(payload)
        except ValueError:
            continue
        if chunk.get("error"):  # passerelles (OpenRouter, DeepSeek…) : erreur dans un corps HTTP 200
            error = chunk["error"]
            raise AIError(f"{p.name} : {error.get('message') if isinstance(error, dict) else error}")
        result.model = chunk.get("model") or result.model
        choice = (chunk.get("choices") or [{}])[0]
        text = (choice.get("delta") or {}).get("content")
        if text:
            yield text
        if choice.get("finish_reason") and choice["finish_reason"] != "stop":
            result.stop_reason = choice["finish_reason"]
        usage = chunk.get("usage") or {}
        if usage:
            result.input_tokens = int(usage.get("prompt_tokens") or 0)
            result.output_tokens = int(usage.get("completion_tokens") or 0)
    result.model = result.model or model_id


# --- Google Gemini (API generateContent native) -------------------------------------------------------------------

async def _google(cfg: dict, p: Provider, system: str, messages: list[dict],
                  result: StreamResult) -> AsyncIterator[str]:
    model_id = model(cfg)
    url = f"{base_url(cfg)}/models/{model_id}:streamGenerateContent?alt=sse"
    headers = {"Content-Type": "application/json", "x-goog-api-key": api_key(cfg)}
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
                     for m in messages],
        "generationConfig": {"maxOutputTokens": int(cfg.get("ai_max_tokens") or 4000) + THINKING_HEADROOM},
    }
    async for line in _sse(p, url, headers, body, model_id):
        if not line.startswith("data:"):
            continue
        try:
            data = json.loads(line[5:].strip())
        except ValueError:
            continue
        blocked = (data.get("promptFeedback") or {}).get("blockReason")
        if blocked:
            raise AIError(f"Google : invite bloquée ({blocked})")
        candidate = (data.get("candidates") or [{}])[0]
        text = "".join(part.get("text", "") for part in (candidate.get("content") or {}).get("parts") or [])
        if text:
            yield text
        if candidate.get("finishReason") and candidate["finishReason"] != "STOP":
            result.stop_reason = candidate["finishReason"]
        usage = data.get("usageMetadata") or {}
        if usage:
            result.input_tokens = int(usage.get("promptTokenCount") or 0)
            result.output_tokens = int(usage.get("candidatesTokenCount") or 0)
    result.model = model_id
    if p.is_retired_model(model_id):
        result.notices.append(f"Le modèle {model_id} est en cours de retrait chez Google : en choisir un plus récent.")


async def _sse(p: Provider, url: str, headers: dict, body: dict, model_id: str) -> AsyncIterator[str]:
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20, read=600)) as client, \
                client.stream("POST", url, json=body, headers=headers) as response:
            if response.status_code >= 400:
                detail = (await response.aread()).decode("utf-8", "replace")
                raise AIError(_http_error(p.name, response.status_code, model_id, detail))
            async for line in response.aiter_lines():
                yield line
    except httpx.HTTPError as exc:
        raise AIError(f"{p.name} injoignable ({type(exc).__name__}) : vérifier l'adresse et l'accès sortant") from None


# --- Ollama (local) ----------------------------------------------------------------------------------------------

# Fenêtre de contexte demandée à Ollama. Par défaut, Ollama s'en tient à 2 048 ou 4 096 jetons et tronque sans
# prévenir le début de la conversation, c'est-à-dire les données de l'alerte : l'analyse devient alors générique.
OLLAMA_CONTEXT = 16384

async def _ollama(cfg: dict, p: Provider, system: str, messages: list[dict],
                  result: StreamResult) -> AsyncIterator[str]:
    url = base_url(cfg) + "/api/chat"
    model_id = model(cfg)
    body = {"model": model_id, "stream": True, "messages": [{"role": "system", "content": system}, *messages],
            "options": {"num_predict": int(cfg.get("ai_max_tokens") or 4000) + THINKING_HEADROOM,
                        "num_ctx": OLLAMA_CONTEXT}}
    try:
        # Modèle local : le premier mot peut tarder (chargement en mémoire, GPU partagé avec d'autres usages)
        async with httpx.AsyncClient(timeout=httpx.Timeout(15, read=600)) as client, \
                client.stream("POST", url, json=body) as response:
            if response.status_code >= 400:
                raise AIError(f"Ollama a répondu HTTP {response.status_code} (modèle « {model_id} » installé ?)")
            async for line in response.aiter_lines():
                if not line.strip():
                    continue
                data = json.loads(line)
                if data.get("error"):
                    raise AIError(f"Ollama : {str(data['error'])[:200]}")
                text = (data.get("message") or {}).get("content", "")
                if text:
                    yield text
                if data.get("done"):
                    result.model = model_id
                    reason = data.get("done_reason", "stop")
                    result.stop_reason = "" if reason == "stop" else reason
                    result.input_tokens = int(data.get("prompt_eval_count") or 0)
                    result.output_tokens = int(data.get("eval_count") or 0)
    except httpx.HTTPError as exc:
        raise AIError(f"Serveur Ollama injoignable ({type(exc).__name__}) : vérifier l'adresse") from None


# --- Liste des modèles (LMU models.ts) ----------------------------------------------------------------------------

async def list_models(cfg: dict, provider_id: str) -> tuple[list[dict], str]:
    """Modèles réellement disponibles chez le fournisseur (clé enregistrée), triés du plus récent au plus ancien.
    Échec (hors ligne, clé absente ou refusée) : liste de repli statique et message d'explication."""
    p = provider(cfg, provider_id)
    fallback = [{"id": i, "label": label} for i, label in p.fallback_models]
    key = api_key(cfg, p.id)
    if p.needs_key and not key:
        return fallback, "Clé d'API non enregistrée : liste de repli"
    base = base_url(cfg, p.id)
    headers: dict[str, str] = {}
    if p.kind == "anthropic":
        url, headers = f"{base}/v1/models?limit=100", {"x-api-key": key, "anthropic-version": "2023-06-01"}
    elif p.kind == "google":
        url, headers = f"{base}/models?pageSize=200", {"x-goog-api-key": key}
    elif p.kind == "ollama":
        url = f"{base}/api/tags"
    else:
        url = f"{base}/models"
        if key:
            headers["Authorization"] = f"Bearer {key}"
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(url, headers=headers)
        if response.status_code >= 400:
            return fallback, _http_error(p.name, response.status_code, "", response.text)
        models = _parse_models(p, response.json())
    except (httpx.HTTPError, ValueError) as exc:
        return fallback, f"{p.name} injoignable ({type(exc).__name__}) : liste de repli"
    return (models, "") if models else (fallback, "Aucun modèle renvoyé : liste de repli")


def _parse_models(p: Provider, raw: dict) -> list[dict]:
    if p.kind == "google":
        items = [{"id": str(m.get("name", "")).removeprefix("models/"), "label": m.get("displayName") or "",
                  "created": 0} for m in raw.get("models") or []
                 if "generateContent" in (m.get("supportedGenerationMethods") or [])]
    elif p.kind == "ollama":
        items = [{"id": m.get("name") or m.get("model") or "", "label": "", "created": 0}
                 for m in raw.get("models") or []]
    elif p.kind == "anthropic":
        items = [{"id": m.get("id", ""), "label": m.get("display_name") or "", "created": m.get("created_at") or ""}
                 for m in raw.get("data") or []]
    else:
        items = [{"id": m.get("id", ""), "label": "", "created": m.get("created") or 0} for m in raw.get("data") or []
                 if not NON_CHAT.search(str(m.get("id", "")))
                 and (not p.model_filter or re.search(p.model_filter, str(m.get("id", "")), re.I))]
    items = [i for i in items if i["id"]]
    items.sort(key=lambda i: str(i["created"]).zfill(20), reverse=True)
    return [{"id": i["id"], "label": i["label"] or i["id"], "retired": p.is_retired_model(i["id"])} for i in items]
