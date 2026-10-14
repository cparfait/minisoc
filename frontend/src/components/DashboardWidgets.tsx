import { Bug, ClipboardList, Clock, Newspaper, ShieldAlert, UserCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { api, query } from "../api";
import { usePolling } from "../hooks";
import { formatDate, formatNumber, moduleLabel, timeAgo } from "../labels";
import type { Alert, Severity } from "../types";
import { Card, Empty, SeverityBadge } from "./ui";

/** Petites listes du tableau de bord configurable (cartes ajoutées depuis « Personnaliser »). */

function AlertLines({ items, empty }: { items: Alert[] | undefined; empty: string }) {
  if (!items?.length) return <Empty>{empty}</Empty>;
  return (
    <ul className="alert-list">
      {items.map((a) => (
        <li key={a.id}>
          <SeverityBadge severity={a.severity} />
          <Link to={`/alerts/${a.id}`}>{a.title}</Link>
          <small>{timeAgo(a.last_seen)}</small>
        </li>
      ))}
    </ul>
  );
}

/** Alertes ouvertes assignées à la personne connectée. */
export function MyAlerts({ lines = 8 }: { lines?: number }) {
  const { data } = usePolling(
    () => api<{ items: Alert[]; total: number }>(`/alerts${query({ status: "new,in_progress,waiting", assignee: "me", sort: "recent", limit: lines })}`),
    [lines],
    30000,
  );
  return (
    <Card title={`Mes alertes${data ? ` (${data.total})` : ""}`} icon={UserCheck}>
      <AlertLines items={data?.items} empty="Aucune alerte ne vous est assignée." />
      {(data?.total ?? 0) > lines && <Link to="/alerts?assignee=me&sort=recent" className="small">Toutes mes alertes</Link>}
    </Card>
  );
}

/** Alertes en retard sur leur échéance de prise en charge ou de traitement. */
export function OverdueAlerts({ lines = 8 }: { lines?: number }) {
  const { data } = usePolling(
    () => api<{ items: Alert[]; total: number }>(`/alerts${query({ status: "new,in_progress", overdue: "true", sort: "severity", limit: lines })}`),
    [lines],
    60000,
  );
  return (
    <Card title={`En retard sur l'échéance${data ? ` (${data.total})` : ""}`} icon={Clock}>
      <AlertLines items={data?.items} empty="Aucune alerte en retard." />
      {(data?.total ?? 0) > lines && <Link to="/alerts?overdue=true" className="small">Toutes les alertes en retard</Link>}
    </Card>
  );
}

interface Incident {
  id: number;
  title: string;
  severity: Severity;
  status: string;
  owner: string;
  alert_count: number;
  updated_at: string | null;
}
const INCIDENT_STATUS: Record<string, string> = { open: "ouvert", investigating: "en investigation", contained: "contenu", closed: "clos" };

/** Incidents en cours. */
export function OpenIncidents({ lines = 8 }: { lines?: number }) {
  const { data } = usePolling(() => api<{ items: Incident[] }>("/incidents?status=open,investigating,contained"), [], 60000);
  const items = data?.items ?? [];
  return (
    <Card title={`Incidents en cours${data ? ` (${items.length})` : ""}`} icon={ShieldAlert}>
      {items.length === 0 ? (
        <Empty>Aucun incident en cours.</Empty>
      ) : (
        <ul className="alert-list">
          {items.slice(0, lines).map((i) => (
            <li key={i.id}>
              <SeverityBadge severity={i.severity} />
              <Link to={`/incidents/${i.id}`}>{i.title}</Link>
              <small>
                {INCIDENT_STATUS[i.status] ?? i.status} · {i.alert_count} alerte(s){i.owner ? ` · ${i.owner}` : ""}
              </small>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

interface FleetCve {
  cve: string;
  machines: number;
  servers: number;
  score: number | null;
  kev: boolean;
  sample: string[];
}

/** Failles activement exploitées (KEV) présentes sur le parc (dernier relevé Cyberwatch). */
export function KevOnFleet({ lines = 8 }: { lines?: number }) {
  const { data } = usePolling(() => api<{ items: FleetCve[]; at: number | null }>(`/cve${query({ kev_only: "true", limit: lines })}`), [lines], 300000);
  return (
    <Card title="Failles activement exploitées présentes (KEV)" icon={Bug}>
      {!data?.at ? (
        <Empty>Cyberwatch n'est pas raccordé.</Empty>
      ) : data.items.length === 0 ? (
        <Empty>Aucune faille du catalogue KEV sur le parc.</Empty>
      ) : (
        <table>
          <tbody>
            {data.items.map((c) => (
              <tr key={c.cve}>
                <td className="nowrap">
                  <Link to={`/cve/${c.cve}`} className="mono">{c.cve}</Link>
                </td>
                <td className="num" title="machines touchées (dont serveurs)">
                  {c.machines} <span className="muted small">({c.servers} srv)</span>
                </td>
                <td className="muted small ellipsis">{c.sample.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <Link to="/cve" className="small">Toutes les CVE du parc</Link>
    </Card>
  );
}

interface CertItem {
  kind: "alerte" | "avis";
  title: string;
  link: string;
  date: string;
}

/** Dernières publications du CERT-FR. */
export function CertFr({ lines = 6 }: { lines?: number }) {
  const { data } = usePolling(() => api<{ certfr: CertItem[] }>("/veille"), [], 600000);
  const items = data?.certfr ?? [];
  return (
    <Card title="CERT-FR : dernières publications" icon={Newspaper}>
      {items.length === 0 ? (
        <Empty>Flux non récupéré (accès Internet du serveur).</Empty>
      ) : (
        <ul className="alert-list">
          {items.slice(0, lines).map((c) => (
            <li key={c.link}>
              <span className={`badge ${c.kind === "alerte" ? "sev-critical" : "sev-low"}`}>{c.kind === "alerte" ? "Alerte" : "Avis"}</span>
              <a href={c.link} target="_blank" rel="noopener noreferrer">{c.title}</a>
              <small>{formatDate(c.date).split(" ")[0]}</small>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** Synthèse chiffrée des alertes ouvertes par outil d'origine. */
export function AlertsByTool() {
  const { data } = usePolling(
    () => api<{ total: number; items: Alert[] }>(`/alerts${query({ status: "new,in_progress,waiting", sort: "recent", limit: 500 })}`),
    [],
    60000,
  );
  const counts = new Map<string, number>();
  for (const a of data?.items ?? []) {
    const tool = a.modules[0] ?? "mini-soc";
    counts.set(tool, (counts.get(tool) ?? 0) + 1);
  }
  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  return (
    <Card title="Alertes ouvertes par outil" icon={ClipboardList}>
      {rows.length === 0 ? (
        <Empty>Aucune alerte ouverte.</Empty>
      ) : (
        <table>
          <tbody>
            {rows.map(([tool, n]) => (
              <tr key={tool}>
                <td>
                  <Link to={tool === "mini-soc" ? "/alerts" : `/alerts?module=${encodeURIComponent(tool)}`}>{tool === "mini-soc" ? "Mini-SOC (corrélations)" : moduleLabel(tool)}</Link>
                </td>
                <td className="num">{formatNumber(n)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
