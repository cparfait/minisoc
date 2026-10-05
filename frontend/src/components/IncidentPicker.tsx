import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { NewIncident } from "../pages/Incidents";
import type { Incident } from "../types";

interface ListResponse {
  items: Incident[];
  categories: Record<string, string>;
}

/**
 * Rattacher des alertes à un incident en cours, ou en créer un nouveau avec elles.
 * Utilisé sur le détail d'une alerte et pour une sélection dans la liste des alertes.
 */
export default function IncidentPicker({ alertIds, defaultTitle = "", onDone, compact = false }: {
  alertIds: number[];
  defaultTitle?: string;
  onDone: () => void;
  compact?: boolean;
}) {
  const [list, setList] = useState<ListResponse | null>(null);
  const [target, setTarget] = useState("");
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<ListResponse>("/incidents?status=open,investigating,contained").then(setList).catch(() => setList(null));
  }, []);

  const attach = async () => {
    setBusy(true);
    setError(null);
    try {
      await api(`/incidents/${target}/alerts`, { method: "POST", body: { alert_ids: alertIds } });
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (creating && list) {
    return (
      <NewIncident categories={list.categories} alertIds={alertIds} defaultTitle={defaultTitle}
        onCancel={() => setCreating(false)} onCreated={() => onDone()} />
    );
  }
  return (
    <div className={`incident-picker ${compact ? "row" : "stack"}`}>
      {list && list.items.length > 0 && (
        <div className="row">
          <select value={target} onChange={(e) => setTarget(e.target.value)} aria-label="Incident en cours">
            <option value="">Rattacher à un incident en cours…</option>
            {list.items.map((i) => (
              <option key={i.id} value={i.id}>
                n° {i.id} · {i.title}
              </option>
            ))}
          </select>
          <button type="button" disabled={!target || busy} onClick={attach}>
            Rattacher
          </button>
        </div>
      )}
      <button type="button" onClick={() => setCreating(true)} disabled={!list}>
        Nouvel incident{alertIds.length > 1 ? ` avec ces ${alertIds.length} alertes` : " à partir de cette alerte"}
      </button>
      {error && <p className="form-error">{error}</p>}
    </div>
  );
}

export function IncidentBadge({ id }: { id: number }) {
  return (
    <Link to={`/incidents/${id}`} className="incident-badge" title="Alerte rattachée à un incident">
      Incident n° {id}
    </Link>
  );
}
