import { Link2 } from "lucide-react";
import { Link } from "react-router-dom";
import { api, query } from "../api";
import { usePolling } from "../hooks";
import { formatDate, timeAgo } from "../labels";
import type { Alert, AlertStatus } from "../types";
import { PriorityPill } from "./Priority";
import { Fold, SeverityBadge, StatusBadge } from "./ui";

const OPEN = "new,in_progress,waiting";
const MAX_PER_KIND = 3;
const LIMIT_PER_VALUE = 10;
// Le portail VPN récent du XGS journalise 127.0.0.1 à la place de l'attaquant : aucun lien à en tirer
const isLoopback = (ip: string) => ip === "::1" || ip.startsWith("127.");

interface Lookup {
  param: "host" | "account" | "ip";
  value: string;
  label: string;
}
interface Related {
  alert: Alert;
  via: string[];
}
interface Found {
  items: Related[];
  truncated: boolean; // au moins une valeur a plus d'alertes que la limite
  failed: number; // recherches sans réponse : la liste peut être incomplète
}

async function search(lookups: Lookup[], exclude: number): Promise<Found> {
  const results = await Promise.all(
    lookups.map((l) =>
      api<{ total: number; items: Alert[] }>(
        // Tri par date : le tri par priorité chargerait toutes les alertes en mémoire côté API
        `/alerts${query({ status: OPEN, [l.param]: l.value, sort: "recent", limit: LIMIT_PER_VALUE })}`,
      ).then((r) => ({ lookup: l, ...r }), () => null),
    ),
  );
  const byId = new Map<number, Related>();
  let truncated = false;
  for (const r of results) {
    if (!r) continue;
    truncated ||= r.total > r.items.length;
    for (const alert of r.items) {
      if (alert.id === exclude) continue;
      const entry = byId.get(alert.id) ?? { alert, via: [] };
      entry.via.push(r.lookup.label);
      byId.set(alert.id, entry);
    }
  }
  const items = [...byId.values()].sort(
    (a, b) => b.via.length - a.via.length || (b.alert.priority ?? 0) - (a.alert.priority ?? 0) || b.alert.last_seen.localeCompare(a.alert.last_seen),
  );
  return { items, truncated, failed: results.filter((r) => !r).length };
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
  const lookups: Lookup[] = [
    ...hosts.slice(0, MAX_PER_KIND).map((value) => ({ param: "host" as const, value, label: `machine ${value}` })),
    ...users.slice(0, MAX_PER_KIND).map((value) => ({ param: "account" as const, value, label: `compte ${value}` })),
    ...usableIps.slice(0, MAX_PER_KIND).map((value) => ({ param: "ip" as const, value, label: `IP ${value}` })),
  ];
  const key = lookups.map((l) => `${l.param}=${l.value}`).join("\n");
  const { data, error } = usePolling(() => (lookups.length ? search(lookups, alertId) : Promise.resolve(null)), [key, alertId], 0);
  if (!lookups.length) return null;

  const capped = hosts.length > MAX_PER_KIND || users.length > MAX_PER_KIND || usableIps.length > MAX_PER_KIND;
  const count = data?.items.length ?? 0;
  const incomplete = !!error || !!data?.failed;
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
      {incomplete && <p className="form-error">Recherche incomplète : d'autres alertes liées peuvent exister.</p>}
      {count > 0 && (
        <ul className="related-list">
          {data?.items.map(({ alert, via }) => (
            <li key={alert.id}>
              <PriorityPill score={alert.priority} reasons={alert.priority_reasons} />
              <SeverityBadge severity={alert.severity} />
              <div className="related-main">
                <Link to={`/alerts/${alert.id}`} title={alert.title}>{alert.title}</Link>
                <div className="muted small">{via.join(" · ")}</div>
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
          {data?.truncated && `Au plus ${LIMIT_PER_VALUE} alertes, les plus récentes, par valeur recherchée.`}
        </p>
      )}
    </Fold>
  );
}
