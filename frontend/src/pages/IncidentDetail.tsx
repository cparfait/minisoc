import { ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { canEdit, useUser } from "../App";
import { Card, ErrorBanner, PageHeader, SeverityBadge, StatusBadge } from "../components/ui";
import { usePolling } from "../hooks";
import { SEVERITIES, SEVERITY_LABEL, formatDate, timeAgo } from "../labels";
import type { Alert, AlertStatus, Incident, Severity } from "../types";

interface Entry {
  id: number;
  ts: string;
  actor: string;
  kind: string;
  detail: string;
}
interface Detail extends Incident {
  alerts: Alert[];
  entries: Entry[];
  categories: Record<string, string>;
  statuses: Record<string, string>;
}

const KIND_LABEL: Record<string, string> = {
  created: "Création",
  note: "Note",
  action: "Action menée",
  status: "Statut",
  alert_added: "Alerte rattachée",
  alert_removed: "Alerte détachée",
  update: "Modification",
};
const NEXT_STEPS: Record<string, string> = {
  open: "Qualifier : périmètre (comptes, postes, données), gravité, et désigner un responsable.",
  investigating: "Contenir : isoler les postes, désactiver ou réinitialiser les comptes, bloquer les adresses.",
  contained: "Remédier et revenir à la normale, puis rédiger la conclusion (cause, impact, mesures) et clore.",
  closed: "Incident clos : rapport disponible pour l'archivage et le retour d'expérience.",
};

export default function IncidentDetail() {
  const { id } = useParams();
  const user = useUser();
  const editable = canEdit(user);
  const { data, error, reload } = usePolling(() => api<Detail>(`/incidents/${id}`), [id], 30000);
  const [note, setNote] = useState("");
  const [kind, setKind] = useState<"note" | "action">("note");
  const [conclusion, setConclusion] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    if (data) {
      setConclusion(data.conclusion);
      setDescription(data.description);
    }
    // Initialisation à l'ouverture seulement (pas à chaque rafraîchissement)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.id]);

  if (!data) return <ErrorBanner error={error} />;

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      await reload();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };
  const patch = (body: Record<string, unknown>) => run(() => api(`/incidents/${data.id}`, { method: "PATCH", body }));
  const addNote = () =>
    run(async () => {
      await api(`/incidents/${data.id}/entries`, { method: "POST", body: { kind, detail: note } });
      setNote("");
    });
  const detach = (alertId: number) =>
    run(() => api(`/incidents/${data.id}/alerts`, { method: "POST", body: { alert_ids: [alertId], remove: true } }));
  const report = async () => {
    const res = await fetch(`/api/incidents/${data.id}/report`, { credentials: "same-origin" });
    if (!res.ok) return setActionError(`Rapport indisponible (HTTP ${res.status})`);
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident-${data.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };
  const closed = data.status === "closed";

  return (
    <>
      <PageHeader title={`Incident n° ${data.id} : ${data.title}`} icon={ShieldAlert}>
        <SeverityBadge severity={data.severity} />
        <span className={`incident-status incident-${data.status}`}>{data.statuses[data.status]}</span>
        <button type="button" onClick={report}>
          Rapport (.md)
        </button>
      </PageHeader>
      <p className="muted breadcrumb">
        <Link to="/incidents">Incidents</Link> / n° {data.id} · ouvert {timeAgo(data.created_at)} par {data.created_by}
      </p>
      <ErrorBanner error={error ?? actionError} />
      <p className="incident-next">{NEXT_STEPS[data.status]}</p>

      <div className="grid-2 detail">
        <Card title="Informations">
          <div className="stack">
            <div className="row">
              <label>
                Statut
                <select value={data.status} disabled={!editable || busy}
                  onChange={(e) => patch(e.target.value === "closed" ? { status: "closed", conclusion } : { status: e.target.value })}>
                  {Object.entries(data.statuses).map(([k, l]) => (
                    <option key={k} value={k}>
                      {l}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Sévérité
                <select value={data.severity} disabled={!editable || busy} onChange={(e) => patch({ severity: e.target.value as Severity })}>
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {SEVERITY_LABEL[s]}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Catégorie
                <select value={data.category} disabled={!editable || busy} onChange={(e) => patch({ category: e.target.value })}>
                  {Object.entries(data.categories).map(([k, l]) => (
                    <option key={k} value={k}>
                      {l}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="row">
              <span>
                Responsable : <strong>{data.owner ?? "—"}</strong>
              </span>
              {editable && data.owner !== user?.username && (
                <button type="button" disabled={busy} onClick={() => patch({ owner: user?.username })}>
                  M'en charger
                </button>
              )}
            </div>
            <label className="checkbox">
              <input type="checkbox" checked={data.personal_data} disabled={!editable || busy}
                onChange={(e) => patch({ personal_data: e.target.checked })} />
              Données personnelles concernées (violation à évaluer : notification CNIL sous 72 h si risque pour les
              personnes)
            </label>
            <label>
              Description
              <textarea rows={4} value={description} disabled={!editable} onChange={(e) => setDescription(e.target.value)} />
            </label>
            {editable && description !== data.description && (
              <button type="button" disabled={busy} onClick={() => patch({ description })}>
                Enregistrer la description
              </button>
            )}
            <label>
              Conclusion {!closed && <span className="muted">(obligatoire pour clore : cause, impact, mesures prises)</span>}
              <textarea rows={4} value={conclusion} disabled={!editable} onChange={(e) => setConclusion(e.target.value)} />
            </label>
            {editable && (
              <div className="row">
                {conclusion !== data.conclusion && (
                  <button type="button" disabled={busy} onClick={() => patch({ conclusion })}>
                    Enregistrer la conclusion
                  </button>
                )}
                {!closed && (
                  <button type="button" className="primary" disabled={busy || conclusion.trim().length < 20}
                    onClick={() => patch({ conclusion, status: "closed", close_alerts: true })}>
                    Clore l'incident et ses alertes
                  </button>
                )}
              </div>
            )}
          </div>
        </Card>

        <Card title="Chronologie">
          {editable && (
            <div className="stack incident-note">
              <div className="segmented" role="group" aria-label="Type d'entrée">
                <button type="button" className={kind === "note" ? "active" : ""} onClick={() => setKind("note")}>
                  Note
                </button>
                <button type="button" className={kind === "action" ? "active" : ""} onClick={() => setKind("action")}>
                  Action menée
                </button>
              </div>
              <textarea rows={2} value={note} maxLength={8000} onChange={(e) => setNote(e.target.value)}
                placeholder={kind === "action" ? "Ex. : poste PC-RH-01 isolé depuis HarfangLab" : "Constat, hypothèse, échange…"} />
              <button type="button" className="primary" disabled={busy || !note.trim()} onClick={addNote}>
                Ajouter
              </button>
            </div>
          )}
          <ol className="timeline">
            {[...data.entries].reverse().map((e) => (
              <li key={e.id} className={`entry-${e.kind}`}>
                <time>{formatDate(e.ts)}</time> · <strong>{e.actor}</strong> · {KIND_LABEL[e.kind] ?? e.kind}
                {e.detail && <div className="pre">{e.detail}</div>}
              </li>
            ))}
          </ol>
        </Card>
      </div>

      <Card title={`Alertes rattachées (${data.alerts.length})`}>
        {!data.alerts.length ? (
          <p className="muted">
            Aucune alerte. Rattachez-en depuis la <Link to="/alerts">liste des alertes</Link> (cases à cocher) ou depuis
            le détail d'une alerte.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Sévérité</th>
                <th>Alerte</th>
                <th>Première détection</th>
                <th>Dernière détection</th>
                <th>Statut</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.alerts.map((a) => (
                <tr key={a.id}>
                  <td>
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td>
                    <Link to={`/alerts/${a.id}`}>
                      n° {a.id} · {a.title}
                    </Link>
                    <div className="muted small">{a.rule_id} · {a.entity_key}</div>
                  </td>
                  <td className="nowrap small">{formatDate(a.first_seen)}</td>
                  <td className="nowrap small">{formatDate(a.last_seen)}</td>
                  <td>
                    <StatusBadge status={a.status as AlertStatus} />
                  </td>
                  <td>
                    {editable && !closed && (
                      <button type="button" className="link" disabled={busy} onClick={() => detach(a.id)}>
                        Détacher
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
