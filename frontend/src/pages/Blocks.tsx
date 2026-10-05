import { Ban } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { canEdit, useUser } from "../App";
import { Empty, ErrorBanner, PageHeader } from "../components/ui";
import { usePolling } from "../hooks";
import { formatDate, timeAgo } from "../labels";

interface BlockItem {
  id: number;
  ip: string;
  reason: string;
  alert_id: number | null;
  status: "active" | "removed" | "failed";
  detail: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  removed_at: string | null;
  removed_by: string;
}

const STATUS = { active: "Actif", removed: "Levé", failed: "Échec" };

export default function Blocks() {
  const user = useUser();
  const [filter, setFilter] = useState("active");
  const { data, error, reload } = usePolling(() => api<{ items: BlockItem[] }>(`/response/blocks${filter ? `?status=${filter}` : ""}`), [filter], 30000);
  const [actionError, setActionError] = useState<string | null>(null);

  const remove = async (b: BlockItem) => {
    if (!window.confirm(`Débloquer ${b.ip} sur le pare-feu ?`)) return;
    setActionError(null);
    try {
      await api(`/response/blocks/${b.id}`, { method: "DELETE" });
      await reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <>
      <PageHeader title="Blocages d'IP" icon={Ban} subtitle="Adresses bloquées sur le pare-feu Sophos XGS" />
      <p className="muted">
        Adresses bloquées sur le pare-feu depuis le Mini-SOC. Chaque blocage est levé automatiquement à son échéance.
      </p>
      <div className="filters">
        <div className="segmented">
          {[["active", "Actifs"], ["removed", "Levés"], ["failed", "Échecs"], ["", "Tous"]].map(([v, l]) => (
            <button key={l} className={filter === v ? "active" : ""} onClick={() => setFilter(v)}>{l}</button>
          ))}
        </div>
      </div>
      <ErrorBanner error={error ?? actionError} />
      {data && !data.items.length ? (
        <Empty>Aucun blocage.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Adresse IP</th>
              <th>Motif</th>
              <th>Par</th>
              <th>Depuis</th>
              <th>Échéance</th>
              <th>État</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data?.items.map((b) => (
              <tr key={b.id}>
                <td className="mono"><Link to={`/events?ip=${encodeURIComponent(b.ip)}`}>{b.ip}</Link></td>
                <td>
                  {b.alert_id ? <Link to={`/alerts/${b.alert_id}`}>{b.reason}</Link> : b.reason}
                  {b.detail && <div className="muted small">{b.detail}</div>}
                </td>
                <td>{b.created_by}</td>
                <td title={formatDate(b.created_at)}>{timeAgo(b.created_at)}</td>
                <td>{b.status === "removed" ? `levé ${timeAgo(b.removed_at)} (${b.removed_by})` : formatDate(b.expires_at)}</td>
                <td>{STATUS[b.status]}</td>
                <td>
                  {b.status === "active" && canEdit(user) && (
                    <button className="link danger" onClick={() => remove(b)}>Débloquer</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
