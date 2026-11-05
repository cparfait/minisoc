import { Link2 } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { usePolling } from "../hooks";
import { formatDate, timeAgo } from "../labels";
import type { Alert, AlertStatus } from "../types";
import { PriorityPill } from "./Priority";
import { Fold, SeverityBadge, StatusBadge } from "./ui";

const MAX_PER_KIND = 3; // mêmes limites que l'API
const LIMIT = 30;
// Le portail VPN récent du XGS journalise 127.0.0.1 à la place de l'attaquant : aucun lien à en tirer
const isLoopback = (ip: string) => ip === "::1" || ip.startsWith("127.");

interface Found {
  items: (Alert & { via: string[] })[];
  truncated: boolean; // d'autres alertes existent au-delà de la limite
}

/** Autres alertes ouvertes sur la même machine, le même compte ou la même IP. Chargées une fois à l'ouverture. */
export default function RelatedAlerts({ alertId, hosts, users, ips, ipsSkipped = false }: {
  alertId: number;
  hosts: string[];
  users: string[];
  ips: string[];
  ipsSkipped?: boolean; // regroupement : ses IP ne sont pas recherchées
}) {
  const usableIps = ips.filter((ip) => !isLoopback(ip));
  const search = new URLSearchParams({ exclude: String(alertId) });
  hosts.slice(0, MAX_PER_KIND).forEach((v) => search.append("host", v));
  users.slice(0, MAX_PER_KIND).forEach((v) => search.append("account", v));
  usableIps.slice(0, MAX_PER_KIND).forEach((v) => search.append("ip", v));
  const empty = search.size === 1;
  const { data, error } = usePolling(() => (empty ? Promise.resolve(null) : api<Found>(`/alerts/related?${search}`)), [search.toString()], 0);
  if (empty) return null;

  const capped = hosts.length > MAX_PER_KIND || users.length > MAX_PER_KIND || usableIps.length > MAX_PER_KIND;
  const count = data?.items.length ?? 0;
  const incomplete = !!error;
  const title = data ? `Alertes liées (${count}${data.truncated ? "+" : ""})` : "Alertes liées";
  const hint = !data && !error
    ? "recherche en cours…"
    : count === 0 && !incomplete
      ? capped || ipsSkipped
        ? "aucune autre alerte ouverte sur les valeurs recherchées"
        : "aucune autre alerte ouverte sur ces machines, comptes ou IP"
      : "autres alertes ouvertes : même machine, compte ou IP";

  return (
    // Clé : l'ouverture par défaut dépend du résultat, connu après le montage du bloc
    <Fold key={data ? "loaded" : "loading"} title={title} icon={Link2} className="card related-alerts" hint={hint} defaultOpen={count > 0 || incomplete}>
      {incomplete && <p className="form-error">Recherche impossible : d'autres alertes liées peuvent exister.</p>}
      {count > 0 && (
        <ul className="related-list">
          {data?.items.map((alert) => (
            <li key={alert.id}>
              <PriorityPill score={alert.priority} reasons={alert.priority_reasons} />
              <SeverityBadge severity={alert.severity} />
              <div className="related-main">
                <Link to={`/alerts/${alert.id}`} title={alert.title}>{alert.title}</Link>
                <div className="muted small">{alert.via.join(" · ")}</div>
              </div>
              <StatusBadge status={alert.status as AlertStatus} />
              <span className="muted small nowrap" title={formatDate(alert.last_seen)}>{timeAgo(alert.last_seen)}</span>
            </li>
          ))}
        </ul>
      )}
      {count === 0 && !incomplete && <p className="muted small">Aucune autre alerte ouverte ne cite les valeurs recherchées.</p>}
      {(capped || ipsSkipped || data?.truncated) && (
        <p className="muted small related-note">
          {capped && `Recherche limitée aux ${MAX_PER_KIND} premières valeurs par type. `}
          {ipsSkipped && "Les IP de ce regroupement ne sont pas recherchées. "}
          {data?.truncated && `Au plus ${LIMIT} alertes, les plus récentes.`}
        </p>
      )}
    </Fold>
  );
}
