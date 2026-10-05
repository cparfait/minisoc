import { ShieldAlert } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { canEdit, useUser } from "../App";
import { Empty, ErrorBanner, PageHeader, SeverityBadge } from "../components/ui";
import { usePolling } from "../hooks";
import { SEVERITIES, SEVERITY_LABEL, formatDate, timeAgo } from "../labels";
import type { Incident, Severity } from "../types";

interface ListResponse {
  items: Incident[];
  by_status: Record<string, number>;
  categories: Record<string, string>;
  statuses: Record<string, string>;
}

const FILTERS: [string, string][] = [
  ["open,investigating,contained", "En cours"],
  ["open", "Ouverts"],
  ["investigating", "En investigation"],
  ["contained", "Maîtrisés"],
  ["closed", "Clos"],
  ["", "Tous"],
];

export default function Incidents() {
  const user = useUser();
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "open,investigating,contained";
  const { data, error } = usePolling(() => api<ListResponse>(`/incidents?status=${encodeURIComponent(status)}`), [status], 30000);
  const [creating, setCreating] = useState(false);
  const count = (s: string) => s.split(",").filter(Boolean).reduce((n, k) => n + (data?.by_status[k] ?? 0), 0);
  const total = data ? Object.values(data.by_status).reduce((a, b) => a + b, 0) : 0;

  return (
    <>
      <PageHeader title="Incidents" icon={ShieldAlert} subtitle="Alertes liées, suivies jusqu'à la conclusion">
        {canEdit(user) && (
          <button className="primary" onClick={() => setCreating(true)}>
            Nouvel incident
          </button>
        )}
      </PageHeader>
      <p className="muted">
        Un incident regroupe les alertes d'une même attaque ou d'un même problème (par exemple : échecs VPN, connexion
        réussie puis règle de transfert sur le même compte) et suit l'enquête jusqu'à la conclusion. Pour en créer un à
        partir d'alertes : cocher les alertes dans la liste des alertes, ou depuis le détail d'une alerte.
      </p>
      {creating && data && <NewIncident categories={data.categories} onCancel={() => setCreating(false)} />}
      <div className="filters">
        <div className="segmented" role="group" aria-label="Statut">
          {FILTERS.map(([v, l]) => (
            <button key={l} className={status === v ? "active" : ""} onClick={() => setParams(v ? { status: v } : { status: "" })}>
              {l}
              {data && <span className="count">{v ? count(v) : total}</span>}
            </button>
          ))}
        </div>
      </div>
      <ErrorBanner error={error} />
      {data && !data.items.length ? (
        <Empty>Aucun incident.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Sévérité</th>
              <th>Incident</th>
              <th>Catégorie</th>
              <th className="num">Alertes</th>
              <th>Statut</th>
              <th>Responsable</th>
              <th>Ouvert</th>
              <th>Dernière activité</th>
            </tr>
          </thead>
          <tbody>
            {data?.items.map((i) => (
              <tr key={i.id}>
                <td>
                  <SeverityBadge severity={i.severity} />
                </td>
                <td>
                  <Link to={`/incidents/${i.id}`}>
                    n° {i.id} · {i.title}
                  </Link>
                  {i.personal_data && <span className="intel-tag" title="Données personnelles concernées">RGPD</span>}
                </td>
                <td className="small">{data.categories[i.category] ?? i.category}</td>
                <td className="num">{i.alert_count}</td>
                <td>
                  <span className={`incident-status incident-${i.status}`}>{data.statuses[i.status] ?? i.status}</span>
                </td>
                <td>{i.owner ?? "—"}</td>
                <td className="nowrap small">{formatDate(i.created_at)}</td>
                <td className="nowrap" title={formatDate(i.updated_at)}>
                  {timeAgo(i.updated_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/** Création d'un incident (éventuellement avec des alertes : `alertIds`). */
export function NewIncident({ categories, alertIds = [], defaultTitle = "", onCancel, onCreated }: {
  categories: Record<string, string>;
  alertIds?: number[];
  defaultTitle?: string;
  onCancel: () => void;
  onCreated?: (id: number) => void;
}) {
  const navigate = useNavigate();
  const [title, setTitle] = useState(defaultTitle);
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("autre");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const created = await api<Incident>("/incidents", {
        method: "POST",
        body: { title, description, category, severity: severity || null, alert_ids: alertIds },
      });
      if (onCreated) onCreated(created.id);
      else navigate(`/incidents/${created.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card stack incident-form" onSubmit={submit}>
      <h2>Nouvel incident{alertIds.length > 0 && ` avec ${alertIds.length} alerte(s)`}</h2>
      <label>
        Titre
        <input value={title} onChange={(e) => setTitle(e.target.value)} required minLength={3} maxLength={300}
          placeholder="Ex. : compromission du compte de j.dupont" autoFocus />
      </label>
      <div className="row">
        <label>
          Catégorie
          <select value={category} onChange={(e) => setCategory(e.target.value)}>
            {Object.entries(categories).map(([k, l]) => (
              <option key={k} value={k}>
                {l}
              </option>
            ))}
          </select>
        </label>
        <label>
          Sévérité
          <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "")}>
            <option value="">{alertIds.length ? "Celle de l'alerte la plus grave" : "Moyenne"}</option>
            {SEVERITIES.filter((s) => s !== "info").map((s) => (
              <option key={s} value={s}>
                {SEVERITY_LABEL[s]}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label>
        Description (ce que l'on sait au départ)
        <textarea rows={3} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={8000} />
      </label>
      {error && <p className="form-error">{error}</p>}
      <div className="row">
        <button type="submit" className="primary" disabled={busy || title.trim().length < 3}>
          Créer l'incident
        </button>
        <button type="button" className="link" onClick={onCancel}>
          Annuler
        </button>
      </div>
    </form>
  );
}
