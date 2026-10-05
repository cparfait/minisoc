"""Fournisseurs d'IA : reprise du connecteur de LMU Stats Viewer (`src/lib/ai/providers/`), côté serveur.

Fournisseurs intégrés (mêmes adresses, modèles de repli et liens de documentation que LMU) : OpenAI, Anthropic,
Google Gemini, OpenRouter, DeepSeek, Mistral, Ollama ; et des **fournisseurs personnalisés** compatibles OpenAI
ajoutés par l'administrateur (nom + adresse de base : Groq, xAI, Together, LM Studio, vLLM, passerelle
d'entreprise…). Une clé par fournisseur, chiffrée dans les réglages ; le navigateur ne la reçoit jamais.

Sans dépendance lourde : importé par les réglages et le catalogue des intégrations.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse

THINKING_HEADROOM = 1024  # LMU : les modèles à réflexion décomptent leurs jetons de raisonnement du plafond de sortie
# LMU openai-compat.ts : exclut les modèles non conversationnels de la liste
NON_CHAT = re.compile(r"embedding|whisper|tts|dall|moderation|audio|realtime|image|vision-?embed|rerank", re.I)
CUSTOM_ID = re.compile(r"^custom-[a-z0-9]{8}$")


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    kind: str  # anthropic | google | openai | ollama
    needs_key: bool = True
    base_url: str = ""  # racine de l'API (openai : …/v1 ; ollama : http://serveur:11434)
    fallback_models: tuple[tuple[str, str], ...] = ()
    docs_url: str = ""
    max_tokens_field: str = "max_tokens"
    model_filter: str = ""  # expression régulière des identifiants conversationnels (OpenAI)
    custom: bool = False
    default_model: str = ""

    def is_retired_model(self, model: str) -> bool:
        """LMU google.ts : générations Gemini 1.x et 2.x arrêtées ou en cours de retrait."""
        return self.id == "google" and bool(re.match(r"^(models/)?gemini-[012](\D|$)", model.strip(), re.I))


BUILTIN: dict[str, Provider] = {p.id: p for p in (
    Provider("openai", "OpenAI (GPT)", "openai", base_url="https://api.openai.com/v1",
             fallback_models=(("gpt-5-mini", "gpt-5-mini"), ("gpt-5.2", "gpt-5.2"), ("gpt-5.5", "gpt-5.5")),
             docs_url="https://platform.openai.com/docs/models", max_tokens_field="max_completion_tokens",
             model_filter=r"^(gpt-|o\d|chatgpt)"),
    Provider("anthropic", "Anthropic (Claude)", "anthropic", base_url="https://api.anthropic.com",
             fallback_models=(("claude-opus-5-5", "Claude Opus 5.5"), ("claude-sonnet-5-5", "Claude Sonnet 5.5"),
                              ("claude-haiku-4-5", "Claude Haiku 4.5")),
             docs_url="https://docs.claude.com/en/docs/about-claude/models/overview", default_model="claude-opus-5-5"),
    Provider("google", "Google (Gemini)", "google", base_url="https://generativelanguage.googleapis.com/v1beta",
             fallback_models=(("gemini-3.7-flash", "Gemini 3.7 Flash"), ("gemini-3.6-flash", "Gemini 3.6 Flash"),
                              ("gemini-3.5-flash-lite", "Gemini 3.5 Flash Lite")),
             docs_url="https://ai.google.dev/gemini-api/docs/models"),
    Provider("openrouter", "OpenRouter", "openai", base_url="https://openrouter.ai/api/v1",
             fallback_models=(("meta-llama/llama-3.3-70b-instruct:free", "Llama 3.3 70B (gratuit)"),
                              ("deepseek/deepseek-chat-v3-0324:free", "DeepSeek V3 (gratuit)")),
             docs_url="https://openrouter.ai/models"),
    Provider("deepseek", "DeepSeek", "openai", base_url="https://api.deepseek.com",
             fallback_models=(("deepseek-chat", "deepseek-chat (V3)"), ("deepseek-reasoner", "deepseek-reasoner (R1)")),
             docs_url="https://api-docs.deepseek.com/quick_start/pricing"),
    Provider("mistral", "Mistral", "openai", base_url="https://api.mistral.ai/v1",
             fallback_models=(("mistral-large-latest", "Mistral Large"), ("mistral-medium-latest", "Mistral Medium")),
             docs_url="https://docs.mistral.ai/getting-started/models/models_overview/"),
    Provider("ollama", "Ollama (local)", "ollama", needs_key=False, docs_url="https://ollama.com/library"),
)}


@dataclass
class CustomDef:
    id: str
    name: str
    base_url: str = field(default="")


def new_custom_id() -> str:
    return f"custom-{secrets.token_hex(4)}"


def custom_defs(cfg: dict) -> list[CustomDef]:
    raw = cfg.get("ai_custom_providers") or "[]"
    try:
        items = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return []
    out = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and CUSTOM_ID.match(str(item.get("id", ""))) and item.get("base_url"):
            out.append(CustomDef(str(item["id"]), str(item.get("name") or item["base_url"])[:80],
                                 str(item["base_url"]).strip().rstrip("/")))
    return out


def all_providers(cfg: dict) -> dict[str, Provider]:
    """Intégrés + personnalisés (LMU custom.ts : compatibles OpenAI, clé facultative)."""
    providers = dict(BUILTIN)
    for d in custom_defs(cfg):
        providers[d.id] = Provider(d.id, d.name or "Compatible OpenAI", "openai", needs_key=False, base_url=d.base_url,
                                   custom=True)
    return providers


def provider(cfg: dict, provider_id: str | None = None) -> Provider:
    pid = provider_id or str(cfg.get("ai_provider") or "anthropic")
    return all_providers(cfg).get(pid, BUILTIN["anthropic"])


def provider_keys(cfg: dict) -> dict[str, str]:
    raw = cfg.get("ai_provider_keys") or "{}"
    try:
        keys = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except ValueError:
        keys = {}
    return {str(k): str(v) for k, v in keys.items() if v} if isinstance(keys, dict) else {}


def api_key(cfg: dict, provider_id: str | None = None) -> str:
    """Clé du fournisseur ; l'ancien champ unique « Clé d'API (Claude) » reste la clé d'Anthropic."""
    p = provider(cfg, provider_id)
    key = provider_keys(cfg).get(p.id, "")
    if not key and p.id == "anthropic":
        key = cfg.get("ai_api_key") or ""
    return key


def base_url(cfg: dict, provider_id: str | None = None) -> str:
    p = provider(cfg, provider_id)
    if p.kind == "ollama":
        return (cfg.get("ai_base_url") or "http://host.docker.internal:11434").rstrip("/")
    return p.base_url.rstrip("/")


def model(cfg: dict) -> str:
    return str(cfg.get("ai_model") or provider(cfg).default_model or "")


def is_local(cfg: dict, provider_id: str | None = None) -> bool:
    """Modèle hébergé sur le réseau : rien ne sort, la pseudonymisation est inutile."""
    p = provider(cfg, provider_id)
    if p.kind == "ollama":
        return True
    if not p.custom:
        return False
    host = (urlparse(base_url(cfg, p.id)).hostname or "").lower()
    if host in ("localhost", "host.docker.internal") or host.endswith((".local", ".lan", ".internal")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback


def configured(cfg: dict) -> bool:
    if not cfg.get("ai_enabled"):
        return False
    p = provider(cfg)
    if p.needs_key and not api_key(cfg):
        return False
    return bool(model(cfg))


def public_list(cfg: dict) -> list[dict]:
    """Fournisseurs pour l'interface (jamais les clés : seulement « clé enregistrée »)."""
    out = []
    for p in all_providers(cfg).values():
        out.append({
            "id": p.id, "name": p.name, "kind": p.kind, "needs_key": p.needs_key, "custom": p.custom,
            "base_url": p.base_url if p.custom else "", "docs_url": p.docs_url,
            "fallback_models": [{"id": i, "label": label} for i, label in p.fallback_models],
            "key_set": bool(api_key(cfg, p.id)),
            "local": is_local(cfg, p.id),
        })
    return out
