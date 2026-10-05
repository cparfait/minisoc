"""Connecteur IA repris de LMU Stats Viewer : fournisseurs compatibles OpenAI, Gemini natif, personnalisés,
liste des modèles, clés par fournisseur."""

import json

import httpx
import pytest

from minisoc.ai import providers
from minisoc.ai.catalog import THINKING_HEADROOM, api_key, configured, is_local, public_list
from minisoc.ai.providers import AIError, StreamResult, list_models, stream_chat

CUSTOM = json.dumps([{"id": "custom-0a1b2c3d", "name": "vLLM interne", "base_url": "http://10.1.0.20:8000/v1"}])


def sse(*chunks):
    return "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n"


@pytest.fixture
def http(monkeypatch):
    state = {"handler": None, "requests": []}
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        def handle(request):
            state["requests"].append(request)
            return state["handler"](request)

        kwargs["transport"] = httpx.MockTransport(handle)
        return real(*args, **kwargs)

    monkeypatch.setattr(providers.httpx, "AsyncClient", factory)
    return state


async def collect(cfg):
    result = StreamResult()
    text = "".join([c async for c in stream_chat(cfg, "consignes", [{"role": "user", "content": "bonjour"},
                                                                    {"role": "assistant", "content": "  "},
                                                                    {"role": "user", "content": "suite"}], result)])
    return text, result


async def test_mistral_stream_with_thinking_headroom_and_empty_turns_removed(http):
    http["handler"] = lambda r: httpx.Response(200, text=sse(
        {"model": "mistral-large-latest", "choices": [{"delta": {"content": "## Ana"}}]},
        {"choices": [{"delta": {"content": "lyse"}, "finish_reason": "stop"}]},
        {"choices": [], "usage": {"prompt_tokens": 120, "completion_tokens": 8}},
    ))
    cfg = {"ai_enabled": True, "ai_provider": "mistral", "ai_provider_keys": json.dumps({"mistral": "k"}),
           "ai_model": "mistral-large-latest", "ai_max_tokens": 2000}
    text, result = await collect(cfg)
    request = http["requests"][0]
    body = json.loads(request.content)
    assert text == "## Analyse" and str(request.url) == "https://api.mistral.ai/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer k"
    assert body["max_tokens"] == 2000 + THINKING_HEADROOM
    assert [m["role"] for m in body["messages"]] == ["system", "user", "user"]  # tour vide retiré
    assert (result.model, result.input_tokens, result.output_tokens, result.notices) == (
        "mistral-large-latest", 120, 8, [])


async def test_openai_uses_max_completion_tokens_and_reports_truncation(http):
    http["handler"] = lambda r: httpx.Response(200, text=sse(
        {"choices": [{"delta": {"content": "début"}, "finish_reason": "length"}]}))
    cfg = {"ai_enabled": True, "ai_provider": "openai", "ai_provider_keys": json.dumps({"openai": "k"}),
           "ai_model": "gpt-5.2"}
    _, result = await collect(cfg)
    assert "max_completion_tokens" in json.loads(http["requests"][0].content)
    assert result.notices == ["Réponse tronquée (limite de longueur atteinte)."]


async def test_error_inside_http_200_stream_is_raised(http):
    http["handler"] = lambda r: httpx.Response(200, text=sse({"error": {"message": "overloaded"}}))
    cfg = {"ai_enabled": True, "ai_provider": "openrouter", "ai_provider_keys": json.dumps({"openrouter": "k"}),
           "ai_model": "x"}
    with pytest.raises(AIError, match="overloaded"):
        await collect(cfg)


async def test_google_native_key_in_header_not_url(http):
    http["handler"] = lambda r: httpx.Response(200, text=(
        'data: {"candidates":[{"content":{"parts":[{"text":"Bon"}]}}]}\n\n'
        'data: {"candidates":[{"content":{"parts":[{"text":"jour"}]},"finishReason":"STOP"}],'
        '"usageMetadata":{"promptTokenCount":50,"candidatesTokenCount":2}}\n\n'))
    cfg = {"ai_enabled": True, "ai_provider": "google", "ai_provider_keys": json.dumps({"google": "secret-key"}),
           "ai_model": "gemini-3.7-flash"}
    text, result = await collect(cfg)
    request = http["requests"][0]
    body = json.loads(request.content)
    assert text == "Bonjour" and "secret-key" not in str(request.url)
    assert request.headers["x-goog-api-key"] == "secret-key"
    assert body["systemInstruction"] == {"parts": [{"text": "consignes"}]}
    assert result.input_tokens == 50


async def test_custom_provider_without_key_is_local(http):
    http["handler"] = lambda r: httpx.Response(200, text=sse({"choices": [{"delta": {"content": "ok"}}]}))
    cfg = {"ai_enabled": True, "ai_provider": "custom-0a1b2c3d", "ai_custom_providers": CUSTOM, "ai_model": "qwen"}
    assert configured(cfg) and is_local(cfg)
    text, _ = await collect(cfg)
    request = http["requests"][0]
    assert text == "ok" and str(request.url) == "http://10.1.0.20:8000/v1/chat/completions"
    assert "authorization" not in request.headers


async def test_http_errors_are_explained(http):
    http["handler"] = lambda r: httpx.Response(401, json={"error": "invalid key"})
    with pytest.raises(AIError, match="clé d'API refusée"):
        await collect({"ai_enabled": True, "ai_provider": "deepseek",
                       "ai_provider_keys": json.dumps({"deepseek": "x"}), "ai_model": "deepseek-chat"})


async def test_list_models_filters_sorts_and_falls_back(http):
    http["handler"] = lambda r: httpx.Response(200, json={"data": [
        {"id": "gpt-5-mini", "created": 100}, {"id": "text-embedding-3-large", "created": 300},
        {"id": "gpt-5.5", "created": 200}, {"id": "whisper-1", "created": 50}, {"id": "babbage-002", "created": 10}]})
    cfg = {"ai_provider_keys": json.dumps({"openai": "k"})}
    models, warning = await list_models(cfg, "openai")
    assert [m["id"] for m in models] == ["gpt-5.5", "gpt-5-mini"] and warning == ""
    models, warning = await list_models({}, "mistral")  # pas de clé : repli statique
    assert models[0]["id"] == "mistral-large-latest" and "Clé" in warning
    http["handler"] = lambda r: httpx.Response(200, json={"models": [
        {"name": "models/gemini-2.5-pro", "displayName": "Gemini 2.5 Pro",
         "supportedGenerationMethods": ["generateContent"]},
        {"name": "models/embedding-001", "supportedGenerationMethods": ["embedContent"]}]})
    models, _ = await list_models({"ai_provider_keys": json.dumps({"google": "k"})}, "google")
    assert models == [{"id": "gemini-2.5-pro", "label": "Gemini 2.5 Pro", "retired": True}]


def test_keys_per_provider_and_legacy_fallback():
    cfg = {"ai_provider": "anthropic", "ai_api_key": "ancienne", "ai_provider_keys": json.dumps({"mistral": "m"})}
    assert api_key(cfg) == "ancienne" and api_key(cfg, "mistral") == "m" and api_key(cfg, "openai") == ""
    listing = {p["id"]: p for p in public_list({**cfg, "ai_custom_providers": CUSTOM})}
    assert listing["anthropic"]["key_set"] and listing["mistral"]["key_set"] and not listing["openai"]["key_set"]
    assert listing["custom-0a1b2c3d"]["custom"] and listing["custom-0a1b2c3d"]["local"]
    assert "m" not in json.dumps(listing["mistral"]).replace('"', " ").split()  # la clé n'est jamais renvoyée
