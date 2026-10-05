import { ExternalLink } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import ModelPicker from "./ModelPicker";

/**
 * Fournisseurs d'IA : reprise du panneau de LMU Stats Viewer (AiProvidersPanel + AiModelPicker).
 * - liste des fournisseurs intégrés et personnalisés (compatibles OpenAI), clé propre à chacun (jamais réaffichée) ;
 * - modèle choisi dans la liste RÉELLE lue chez le fournisseur ; saisie manuelle en secours (modèle tout juste sorti,
 *   fournisseur muet) ; lien vers la documentation des modèles ; avertissement si le modèle est retiré.
 */

interface ProviderInfo {
  id: string;
  name: string;
  kind: string;
  needs_key: boolean;
  custom: boolean;
  base_url: string;
  docs_url: string;
  fallback_models: { id: string; label: string }[];
  key_set: boolean;
  local: boolean;
}
interface ModelInfo {
  id: string;
  label: string;
  retired?: boolean;
}

export default function AiProviders({ onChanged }: { onChanged?: () => void }) {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [active, setActive] = useState("anthropic");
  const [model, setModel] = useState("");
  const [savedModel, setSavedModel] = useState("");
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [modelsWarning, setModelsWarning] = useState("");
  const [loadingModels, setLoadingModels] = useState(false);
  const [key, setKey] = useState("");
  const [adding, setAdding] = useState(false);
  const [custom, setCustom] = useState({ name: "", base_url: "", key: "" });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    const r = await api<{ active: string; model: string; providers: ProviderInfo[] }>("/ai/providers");
    setProviders(r.providers);
    setActive(r.active);
    setModel(r.model);
    setSavedModel(r.model);
  }, []);

  useEffect(() => {
    load().catch((e) => setMessage({ ok: false, text: String(e) }));
  }, [load]);

  const current = providers.find((p) => p.id === active);

  const refreshModels = useCallback(async () => {
    if (!active) return;
    setLoadingModels(true);
    try {
      const r = await api<{ models: ModelInfo[]; warning: string }>(`/ai/providers/${active}/models`);
      setModels(r.models);
      setModelsWarning(r.warning);
    } catch (e) {
      setModels([]);
      setModelsWarning(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingModels(false);
    }
  }, [active]);

  useEffect(() => {
    refreshModels();
  }, [refreshModels]);

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true);
    setMessage(null);
    try {
      await fn();
      await load();
      setMessage({ ok: true, text: ok });
      onChanged?.();
    } catch (e) {
      setMessage({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  const choose = (id: string) =>
    run(async () => {
      await api("/admin/integrations/ai/config", { method: "PUT", body: { ai_provider: id, ai_model: "" } });
    }, "Fournisseur actif changé : choisir le modèle.");
  const saveKey = () =>
    run(async () => {
      await api(`/ai/providers/${active}/key`, { method: "PUT", body: { key } });
      setKey("");
      await refreshModels();
    }, key.trim() ? "Clé enregistrée." : "Clé supprimée.");
  const saveModel = () =>
    run(() => api("/admin/integrations/ai/config", { method: "PUT", body: { ai_model: model } }), "Modèle enregistré.");
  const addCustom = () =>
    run(async () => {
      const r = await api<{ id: string }>("/ai/custom-providers", { method: "POST", body: custom });
      await api("/admin/integrations/ai/config", { method: "PUT", body: { ai_provider: r.id, ai_model: "" } });
      setCustom({ name: "", base_url: "", key: "" });
      setAdding(false);
    }, "Fournisseur ajouté et activé.");
  const removeCustom = (id: string) =>
    run(() => api(`/ai/custom-providers/${id}`, { method: "DELETE" }), "Fournisseur supprimé.");

  const retired = models.find((m) => m.id === model)?.retired;
  const example = current?.fallback_models[0]?.id;

  return (
    <div className="ai-providers">
      <h3>Fournisseurs d'IA</h3>
      <ul className="ai-provider-list">
        {providers.map((p) => (
          <li key={p.id} className={p.id === active ? "active" : ""}>
            <div className="ai-provider-name">
              <strong>{p.name}</strong>
              <span className="muted small">
                {p.custom ? p.base_url : p.local ? "local : aucune donnée ne sort" : p.kind === "anthropic" ? "cloud, SDK officiel" : "cloud"}
              </span>
            </div>
            <span className={`state-pill ${p.key_set || !p.needs_key ? "state-active" : "state-config"}`}>
              {p.key_set ? "clé enregistrée" : p.needs_key ? "clé requise" : "sans clé"}
            </span>
            {p.id === active ? (
              <span className="state-pill state-waiting">actif</span>
            ) : (
              <button type="button" disabled={busy} onClick={() => choose(p.id)}>
                Utiliser
              </button>
            )}
            {p.custom && (
              <button type="button" className="link danger" disabled={busy} onClick={() => removeCustom(p.id)}>
                Supprimer
              </button>
            )}
          </li>
        ))}
      </ul>

      {adding ? (
        <div className="ai-custom-form stack">
          <div className="row">
            <label>
              Nom
              <input value={custom.name} onChange={(e) => setCustom({ ...custom, name: e.target.value })} placeholder="Groq, vLLM interne…" />
            </label>
            <label className="grow">
              Adresse de base (compatible OpenAI)
              <input value={custom.base_url} onChange={(e) => setCustom({ ...custom, base_url: e.target.value })}
                placeholder="https://api.groq.com/openai/v1 ou http://serveur:8000/v1" />
            </label>
          </div>
          <label>
            Clé d'API (facultative pour un serveur local)
            <input type="password" autoComplete="new-password" value={custom.key} onChange={(e) => setCustom({ ...custom, key: e.target.value })} />
          </label>
          <div className="row">
            <button type="button" className="primary" disabled={busy || !custom.base_url.trim()} onClick={addCustom}>
              Ajouter
            </button>
            <button type="button" className="link" onClick={() => setAdding(false)}>
              Annuler
            </button>
          </div>
        </div>
      ) : (
        <button type="button" className="link" onClick={() => setAdding(true)}>
          + Ajouter un fournisseur personnalisé (compatible OpenAI)
        </button>
      )}

      {current && (
        <div className="ai-active stack">
          <h4>{current.name}</h4>
          {(current.needs_key || current.custom) && (
            <div className="row">
              <label className="grow">
                Clé d'API {current.key_set && <span className="badge status-resolved">définie</span>}
                <input type="password" autoComplete="new-password" value={key} onChange={(e) => setKey(e.target.value)}
                  placeholder={current.key_set ? "laisser vide puis Enregistrer pour supprimer la clé" : "coller la clé"} />
              </label>
              <button type="button" disabled={busy || (!key.trim() && !current.key_set)} onClick={saveKey}>
                {key.trim() ? "Enregistrer la clé" : "Supprimer la clé"}
              </button>
            </div>
          )}
          <div className="row ai-model-row">
            <label className="grow">
              Modèle
              <ModelPicker models={models} value={model} onChange={setModel}
                placeholder={example ? `Rechercher, ou saisir l'identifiant (ex. ${example})` : undefined} />
            </label>
            <button type="button" disabled={loadingModels} onClick={refreshModels} title="Relire la liste chez le fournisseur">
              {loadingModels ? "Lecture…" : "Actualiser la liste"}
            </button>
            <button type="button" className="primary" disabled={busy || !model.trim() || model === savedModel} onClick={saveModel}>
              Enregistrer le modèle
            </button>
          </div>
          {modelsWarning && <p className="muted small">{modelsWarning}</p>}
          {retired && <p className="text-bad small">Ce modèle est retiré ou en cours de retrait chez le fournisseur : en choisir un plus récent.</p>}
          {current.docs_url && (
            <a className="small" href={current.docs_url} target="_blank" rel="noopener noreferrer">
              Liste officielle des modèles ({current.name}) <ExternalLink size={14} />
            </a>
          )}
        </div>
      )}
      {message && <p className={message.ok ? "text-good" : "text-bad"}>{message.text}</p>}
    </div>
  );
}
