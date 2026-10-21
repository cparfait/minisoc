import { Plug } from "lucide-react";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useUser } from "../App";
import AiProviders from "../components/AiProviders";
import Markdown from "../components/Markdown";
import { WordPressAdmin } from "../components/WordPress";
import { Empty, ErrorBanner, PageHeader } from "../components/ui";
import { usePolling } from "../hooks";
import { formatDate, formatNumber, timeAgo } from "../labels";

interface FieldUI {
  key: string;
  label: string;
  kind: "text" | "secret" | "bool" | "int" | "pem" | "list" | "choice";
  help: string;
  placeholder: string;
  choices: [string, string][];
  required: boolean;
}
type State = "active" | "waiting" | "silent" | "not_configured" | "disabled" | "planned";
interface Item {
  id: string;
  name: string;
  vendor: string;
  category: string;
  modes: string[];
  description: string;
  enable_key: string;
  fields: FieldUI[];
  test: string;
  setup: string;
  planned: boolean;
  enabled: boolean;
  state: State;
  missing: string[];
  last_seen: string | null;
  detail: string;
  dropped: number;
  silence_minutes: number;
  modules: string[];
  status_kind: string;
}

const STATE: Record<State, { label: string; cls: string }> = {
  active: { label: "Active", cls: "state-active" },
  waiting: { label: "En attente de données", cls: "state-waiting" },
  silent: { label: "Silencieuse", cls: "state-silent" },
  not_configured: { label: "À configurer", cls: "state-config" },
  disabled: { label: "Désactivée", cls: "state-disabled" },
  planned: { label: "À venir", cls: "state-planned" },
};
/** Tuiles de synthèse (cliquables : filtre) et sections, de ce qui demande une action à ce qui est prévu. */
const TILES: { key: string; label: string; states: State[]; cls: string }[] = [
  { key: "active", label: "En service", states: ["active"], cls: "state-active" },
  { key: "waiting", label: "En attente de données", states: ["waiting"], cls: "state-waiting" },
  { key: "silent", label: "Silencieuses", states: ["silent"], cls: "state-silent" },
  { key: "todo", label: "À configurer", states: ["not_configured"], cls: "state-config" },
  { key: "disabled", label: "Désactivées", states: ["disabled"], cls: "state-disabled" },
  { key: "planned", label: "À venir", states: ["planned"], cls: "state-planned" },
];
const SECTIONS: { title: string; hint: string; states: State[] }[] = [
  { title: "À traiter", hint: "Sources muettes, en attente de leurs premiers journaux ou incomplètes.", states: ["silent", "not_configured", "waiting"] },
  { title: "En service", hint: "", states: ["active"] },
  { title: "Désactivées", hint: "Événements ignorés à la réception, hors surveillance « source silencieuse ».", states: ["disabled"] },
];
const ORDER: State[] = ["silent", "not_configured", "waiting", "active", "disabled", "planned"];

const initials = (name: string) => name.split(/[\s(/]+/).filter(Boolean).slice(0, 2).map((w) => w[0]).join("").toUpperCase();

/** Ce que l'administrateur doit savoir ou faire, en une ligne. */
function nextStep(i: Item): { text: string; tone: "" | "warn" | "bad" } {
  switch (i.state) {
    case "silent":
      return { text: `Plus aucune donnée depuis ${timeAgo(i.last_seen)} (seuil ${i.silence_minutes} min) : vérifier l'envoi.`, tone: "bad" };
    case "not_configured":
      return { text: `À renseigner : ${i.missing.join(", ")}.`, tone: "warn" };
    case "waiting":
      if (i.modes.some((m) => /syslog|nxlog|cef/i.test(m))) return { text: "Aucun journal reçu : configurer l'envoi vers le Mini-SOC (voir Configurer).", tone: "warn" };
      if (i.modes.some((m) => /push/i.test(m))) return { text: "Aucun envoi reçu : déclarer le Mini-SOC dans la console de l'outil.", tone: "warn" };
      return { text: i.detail || "Configurée, en attente des premières données.", tone: "warn" };
    case "active":
      return { text: i.last_seen ? `Données reçues ${timeAgo(i.last_seen)}` : i.detail || "Opérationnelle", tone: "" };
    case "disabled":
      return { text: "Désactivée : ses événements sont ignorés.", tone: "" };
    default:
      return { text: "", tone: "" };
  }
}

export default function Integrations() {
  const user = useUser();
  const isAdmin = user?.role === "admin";
  const { data, error, reload } = usePolling(() => api<{ items: Item[] }>("/integrations"), [], 30000);
  const [search, setSearch] = useState("");
  const [tile, setTile] = useState("");
  const [category, setCategory] = useState("");
  const [open, setOpen] = useState<{ item: Item; tab?: Tab } | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [tests, setTests] = useState<Record<string, { ok: boolean; text: string } | "busy">>({});

  const all = useMemo(() => data?.items ?? [], [data]);
  const categories = useMemo(() => [...new Set(all.map((i) => i.category))].sort(), [all]);
  const visible = useMemo(() => {
    const states = TILES.find((t) => t.key === tile)?.states;
    const needle = search.trim().toLowerCase();
    return all
      .filter((i) => !states || states.includes(i.state))
      .filter((i) => !category || i.category === category)
      .filter((i) => !needle || `${i.name} ${i.vendor} ${i.category} ${i.description}`.toLowerCase().includes(needle))
      .sort((a, b) => ORDER.indexOf(a.state) - ORDER.indexOf(b.state) || a.name.localeCompare(b.name, "fr"));
  }, [all, tile, category, search]);
  const count = (states: State[]) => all.filter((i) => states.includes(i.state)).length;

  const toggle = async (item: Item) => {
    setActionError(null);
    try {
      await api(`/admin/integrations/${item.id}/enabled`, { method: "POST", body: { enabled: !item.enabled } });
      await reload();
      // Activation d'une intégration pas encore raccordée : on ouvre directement son guide d'installation
      if (!item.enabled && item.state !== "active") setOpen({ item: { ...item, enabled: true }, tab: "guide" });
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    }
  };

  const test = async (item: Item) => {
    setTests((t) => ({ ...t, [item.id]: "busy" }));
    try {
      const r = await api<{ ok: boolean; detail: string }>(`/admin/integrations/${item.id}/test`, { method: "POST" });
      setTests((t) => ({ ...t, [item.id]: { ok: r.ok, text: r.detail } }));
    } catch (e) {
      setTests((t) => ({ ...t, [item.id]: { ok: false, text: e instanceof Error ? e.message : String(e) } }));
    }
  };

  const card = (i: Item) => {
    const step = nextStep(i);
    const result = tests[i.id];
    return (
      <article key={i.id} className={`store-card state-border-${i.state}`}>
        <header>
          <span className="store-logo">{initials(i.name)}</span>
          <div className="store-title">
            <strong title={i.name}>{i.name}</strong>
            <small className="muted">
              {i.vendor} · {i.modes.join(", ")}
            </small>
          </div>
          <span className={`state-pill ${STATE[i.state].cls}`}>{STATE[i.state].label}</span>
        </header>
        <p className="store-desc">{i.description}</p>
        {step.text && (
          <p className={`store-step ${step.tone}`}>
            {step.text}
            {i.modules.length > 0 && i.last_seen && (
              <>
                {" · "}
                <Link to={`/events?module=${encodeURIComponent(i.modules[0])}&period=7j`}>Voir les événements reçus</Link>
              </>
            )}
          </p>
        )}
        {i.dropped > 0 && <p className="muted small">{formatNumber(i.dropped)} événement(s) ignoré(s) pendant la désactivation.</p>}
        {result && result !== "busy" && <p className={`small ${result.ok ? "text-good" : "text-bad"}`}>{result.text}</p>}
        <footer>
          <span className="muted small store-category">{i.category}</span>
          {isAdmin && i.test && i.state !== "not_configured" && i.state !== "disabled" && (
            <button type="button" disabled={result === "busy"} onClick={() => test(i)}>
              {result === "busy" ? "Test…" : "Tester"}
            </button>
          )}
          <button type="button" className={i.state === "not_configured" && isAdmin ? "primary" : ""} onClick={() => setOpen({ item: i })}>
            {isAdmin ? "Configurer" : "Détails"}
          </button>
          {isAdmin && i.enable_key && (
            <label className="switch" title={i.enabled ? "Activée : cliquer pour désactiver" : "Désactivée : cliquer pour activer"}>
              <input type="checkbox" checked={i.enabled} onChange={() => toggle(i)} aria-label={`${i.enabled ? "Désactiver" : "Activer"} ${i.name}`} />
              <span />
            </label>
          )}
        </footer>
      </article>
    );
  };

  const planned = visible.filter((i) => i.state === "planned");

  return (
    <>
      <PageHeader title="Intégrations" icon={Plug} subtitle="Solutions raccordées, à configurer ou à venir" />
      <p className="muted">
        Solutions compatibles avec le Mini-SOC. Désactiver une source (effet sous 30 s) ignore ses événements à la réception et la retire de
        la surveillance « source silencieuse ».
      </p>
      <div className="store-tiles" role="group" aria-label="Filtrer par état">
        {TILES.map((t) => {
          const n = count(t.states);
          return (
            <button
              key={t.key}
              type="button"
              className={`store-tile ${tile === t.key ? "active" : ""} ${n === 0 ? "empty" : ""}`}
              onClick={() => setTile(tile === t.key ? "" : t.key)}
              aria-pressed={tile === t.key}
            >
              <span className={`tile-dot ${t.cls}`} />
              <strong>{n}</strong>
              <span>{t.label}</span>
            </button>
          );
        })}
      </div>
      <div className="filters">
        <input type="search" placeholder="Rechercher une solution" value={search} onChange={(e) => setSearch(e.target.value)} />
        <select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Catégorie">
          <option value="">Toutes catégories</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        {(tile || category || search) && (
          <button type="button" className="link" onClick={() => { setTile(""); setCategory(""); setSearch(""); }}>
            Tout afficher
          </button>
        )}
      </div>
      <ErrorBanner error={error ?? actionError} />
      {data && !visible.length && <Empty>Aucune intégration ne correspond.</Empty>}
      {SECTIONS.map((section) => {
        const items = visible.filter((i) => section.states.includes(i.state));
        if (!items.length) return null;
        return (
          <section key={section.title} className="store-section">
            <h2>
              {section.title} <span className="muted">({items.length})</span>
            </h2>
            {section.hint && <p className="muted small">{section.hint}</p>}
            <div className="store-grid">{items.map(card)}</div>
          </section>
        );
      })}
      {planned.length > 0 && (
        <section className="store-section">
          <h2>
            À venir <span className="muted">({planned.length})</span>
          </h2>
          <ul className="store-planned">
            {planned.map((i) => (
              <li key={i.id}>
                <button type="button" className="link" onClick={() => setOpen({ item: i })}>
                  {i.name}
                </button>
                <span className="muted small"> · {i.vendor} · {i.category}</span>
                <div className="muted small">{i.description}</div>
              </li>
            ))}
          </ul>
        </section>
      )}
      {open && (
        <ConfigDialog item={open.item} admin={isAdmin} initialTab={open.tab} onClose={() => { setOpen(null); reload(); }} />
      )}
    </>
  );
}

type Tab = "guide" | "config";

function ConfigDialog({ item, admin, initialTab, onClose }: {
  item: Item;
  admin: boolean;
  initialTab?: Tab;
  onClose: () => void;
}) {
  const editable = admin && !item.planned && item.fields.length > 0;
  const [tab, setTab] = useState<Tab>(
    initialTab ?? (!editable || ["not_configured", "waiting", "planned"].includes(item.state) ? "guide" : "config"),
  );
  const [guide, setGuide] = useState<string | null>(null);
  const [guideError, setGuideError] = useState<string | null>(null);
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [form, setForm] = useState<Record<string, unknown>>({});
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [rules, setRules] = useState<XgsRule[] | null>(null);

  useEffect(() => {
    api<{ markdown: string }>(`/integrations/${item.id}/guide`)
      .then((r) => setGuide(r.markdown))
      .catch((e) => setGuideError(e instanceof Error ? e.message : String(e)));
  }, [item.id]);

  const download = () => {
    if (!guide) return;
    const url = URL.createObjectURL(new Blob([guide], { type: "text/markdown;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `guide-${item.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const readRules = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const r = await api<{ items: XgsRule[] }>("/admin/integrations/xgs_response/rules");
      setRules(r.items);
      setMessage({ ok: true, text: `${r.items.length} règle(s) lue(s), aucune modification effectuée.` });
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (!editable) return;
    api<{ values: Record<string, unknown> }>(`/admin/integrations/${item.id}/config`).then((r) => {
      const plain: Record<string, unknown> = {};
      for (const f of item.fields) {
        const v = r.values[f.key];
        plain[f.key] = f.kind === "secret" ? "" : f.kind === "list" ? ((v as string[]) ?? []).join(", ") : v;
      }
      setValues(r.values);
      setForm(plain);
    }).catch((e) => setMessage({ ok: false, text: String(e) }));
  }, [item, editable]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    const changes: Record<string, unknown> = {};
    for (const f of item.fields) {
      if (f.kind === "secret") {
        if (form[f.key]) changes[f.key] = form[f.key];
      } else {
        const original = f.kind === "list" ? ((values[f.key] as string[]) ?? []).join(", ") : values[f.key];
        if (form[f.key] !== original) changes[f.key] = form[f.key];
      }
    }
    try {
      const r = await api<{ changed: string[] }>(`/admin/integrations/${item.id}/config`, { method: "PUT", body: changes });
      setMessage({ ok: true, text: r.changed.length ? "Enregistré." : "Aucune modification." });
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setBusy(true);
    try {
      const r = await api<{ ok: boolean; detail: string }>(`/admin/integrations/${item.id}/test`, { method: "POST" });
      setMessage({ ok: r.ok, text: r.detail });
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  const set = (k: string, v: unknown) => setForm({ ...form, [k]: v });

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={item.name} onClick={(e) => e.stopPropagation()}>
        <header className="modal-header">
          <div>
            <h2>{item.name}</h2>
            <span className="muted small">{item.vendor} · {item.category} · {item.modes.join(", ")}</span>
          </div>
          <button className="link" onClick={onClose} aria-label="Fermer">✕</button>
        </header>
        <p>{item.description}</p>
        {item.last_seen && <p className="muted small">Dernières données : {formatDate(item.last_seen)}</p>}
        <div className="tabs modal-tabs" role="tablist">
          <button type="button" role="tab" aria-selected={tab === "guide"} className={tab === "guide" ? "active" : ""}
            onClick={() => setTab("guide")}>
            Guide d'installation
          </button>
          {editable && (
            <button type="button" role="tab" aria-selected={tab === "config"} className={tab === "config" ? "active" : ""}
              onClick={() => setTab("config")}>
              Configuration
            </button>
          )}
          <span className="spacer" />
          {tab === "guide" && guide && (
            <button type="button" className="link" onClick={download}>Télécharger le guide</button>
          )}
        </div>
        {tab === "guide" && (
          <div className="modal-guide">
            {guide ? <Markdown text={guide} /> : guideError ? (
              item.setup ? <Markdown text={item.setup} /> : <p className="muted">{guideError}</p>
            ) : <p className="muted">Chargement du guide…</p>}
            {editable && (
              <div className="settings-actions">
                <button type="button" className="primary" onClick={() => setTab("config")}>Passer à la configuration</button>
              </div>
            )}
          </div>
        )}
        {editable && tab === "config" && item.id === "ai" && <AiProviders />}
        {editable && tab === "config" && (
          <form className="settings-form" onSubmit={save}>
            {item.fields.filter((f) => !(item.id === "ai" && (f.key === "ai_provider" || f.key === "ai_model"))).map((f) => (
              <div key={f.key} className={`settings-field ${f.kind === "pem" ? "wide" : ""}`}>
                {f.kind === "bool" ? (
                  <label className="checkbox">
                    <input type="checkbox" checked={Boolean(form[f.key])} onChange={(e) => set(f.key, e.target.checked)} />
                    {f.label}
                  </label>
                ) : (
                  <label>
                    {f.label}{f.required && " *"}
                    {f.kind === "secret" && (values[f.key] as { set?: boolean })?.set && <span className="badge status-resolved"> défini</span>}
                    {f.kind === "pem" ? (
                      <textarea rows={4} className="mono" value={String(form[f.key] ?? "")} onChange={(e) => set(f.key, e.target.value)} />
                    ) : f.kind === "choice" ? (
                      <select value={String(form[f.key] ?? "")} onChange={(e) => set(f.key, e.target.value)}>
                        {f.choices.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                      </select>
                    ) : (
                      <input
                        type={f.kind === "secret" ? "password" : f.kind === "int" ? "number" : "text"}
                        value={String(form[f.key] ?? "")}
                        placeholder={f.kind === "secret" && (values[f.key] as { set?: boolean })?.set ? "laisser vide pour ne pas changer" : f.placeholder}
                        autoComplete={f.kind === "secret" ? "new-password" : "off"}
                        onChange={(e) => set(f.key, f.kind === "int" ? Number(e.target.value) : e.target.value)}
                      />
                    )}
                  </label>
                )}
                {f.help && <small className="muted">{f.help}</small>}
              </div>
            ))}
            <div className="settings-actions">
              <button type="submit" className="primary" disabled={busy}>Enregistrer</button>
              {item.test && <button type="button" disabled={busy} onClick={test}>Tester</button>}
              {item.id === "harfanglab" && (
                <button type="button" disabled={busy} onClick={async () => {
                  setBusy(true);
                  try {
                    const r = await api<{ detail: string }>("/admin/integrations/harfanglab/history", { method: "POST" });
                    setMessage({ ok: true, text: r.detail });
                  } catch (err) {
                    setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
                  } finally {
                    setBusy(false);
                  }
                }}>
                  Relire l'historique
                </button>
              )}
              {item.id === "xgs_response" && (
                <button type="button" disabled={busy} onClick={readRules}>Lire les règles (lecture seule)</button>
              )}
            </div>
          </form>
        )}
        {message && <p className={message.ok ? "text-good" : "text-bad"}>{message.text}</p>}
        {editable && tab === "config" && item.id === "wordpress" && <WordPressAdmin />}
        {rules && rules.length > 0 && (
          <table className="rules-table">
            <thead>
              <tr><th>#</th><th>Règle</th><th>Action</th><th>Zones</th><th>Sources → destinations</th><th>Services</th><th>Journal</th></tr>
            </thead>
            <tbody>
              {rules.map((r, i) => (
                <tr key={`${r.name}-${i}`} className={r.status === "Enable" ? "" : "disabled"}>
                  <td className="muted">{i + 1}</td>
                  <td>{r.name}{r.status !== "Enable" && <span className="muted small"> (désactivée)</span>}</td>
                  <td className={/drop|reject/i.test(r.action) ? "text-bad" : ""}>{r.action || "—"}</td>
                  <td className="small">{r.source_zones.join(", ") || "toutes"} → {r.destination_zones.join(", ") || "toutes"}</td>
                  <td className="small">{r.sources.join(", ") || "toutes"} → {r.destinations.join(", ") || "toutes"}</td>
                  <td className="small">{r.services.join(", ") || "tous"}</td>
                  <td className="small">{r.log === "Enable" ? "oui" : "non"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

interface XgsRule {
  name: string;
  position: string;
  status: string;
  type: string;
  description: string;
  action: string;
  log: string;
  source_zones: string[];
  destination_zones: string[];
  sources: string[];
  destinations: string[];
  services: string[];
}
