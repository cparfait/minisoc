import { Globe, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { usePolling } from "../hooks";
import { formatNumber, timeAgo } from "../labels";
import { Card, Empty } from "./ui";

interface Counters {
  traffic: number;
  blocked: number;
  banned: number;
  suspect: number;
  robot: number;
  analyzed: number;
}
interface SiteState {
  status: string | null;
  auditMode: boolean | null;
  passthroughMode: boolean | null;
  mode: string | null;
  cluster: string | null;
}
interface SiteRow extends Counters {
  site: string;
  state?: SiteState | null;
}
interface Activity {
  enabled: boolean;
  error?: string;
  totals?: Counters;
  sites?: SiteRow[];
  categories?: { name: string; count: number }[];
  at?: string | null;
  days?: number;
}

/** Protection effective d'un site : la pire situation d'abord. */
function protection(state?: SiteState | null): { label: string; className: string } {
  if (!state) return { label: "état inconnu", className: "badge" };
  if (state.passthroughMode) return { label: "non filtré (passthrough)", className: "badge sev-critical" };
  if (state.auditMode) return { label: "mode audit", className: "badge sev-high" };
  if (state.status === "OFFLINE" || state.status === "DNS_ERROR")
    return { label: state.status === "OFFLINE" ? "hors ligne" : "DNS en erreur", className: "badge sev-medium" };
  return { label: "protégé", className: "badge status-resolved" };
}

const percent = (part: number, total: number) => (total ? `${Math.round((100 * part) / total)} %` : "–");

/** Tableau de bord : sites protégés par OGO, trafic et attaques bloquées sur 24 h. Rien tant que le connecteur
 * OGO n'est pas actif (carte affichée par défaut, sans encombrer le tableau de bord des sites sans OGO). */
export function OgoSites({ lines = 8 }: { lines?: number }) {
  const { data } = usePolling(() => api<Activity>("/ogo/summary"), [], 300000);
  if (!data?.enabled) return null;
  const sites = data.sites ?? [];
  const weak = sites.filter((s) => protection(s.state).label !== "protégé" && s.state);
  return (
    <Card title="Sites web protégés par OGO (24 h)" icon={ShieldCheck}>
      {!data.at || !data.totals ? (
        <Empty>Première synthèse en cours (sous un quart d'heure après le raccordement).</Empty>
      ) : (
        <>
          <div className="report-tiles parc-tiles">
            <div className="report-tile">
              <strong>{formatNumber(data.totals.traffic)}</strong>
              <span>requêtes reçues</span>
            </div>
            <div className="report-tile">
              <strong className={data.totals.blocked ? "text-bad" : ""}>{formatNumber(data.totals.blocked)}</strong>
              <span>bloquées</span>
              <small className="muted">{percent(data.totals.blocked, data.totals.traffic)} du trafic</small>
            </div>
            <div className="report-tile">
              <strong>{formatNumber(data.totals.banned)}</strong>
              <span>d'IP bannies</span>
            </div>
            <div className="report-tile">
              <strong className={weak.length ? "text-bad" : ""}>{weak.length}</strong>
              <span>site(s) mal protégé(s)</span>
              <small className="muted">sur {sites.length} · {timeAgo(data.at)}</small>
            </div>
          </div>
          {sites.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>Site</th>
                  <th>Protection</th>
                  <th className="num">Requêtes</th>
                  <th className="num">Bloquées</th>
                  <th className="num">Bannies</th>
                </tr>
              </thead>
              <tbody>
                {[...weak, ...sites.filter((s) => !weak.includes(s))].slice(0, lines).map((s) => {
                  const p = protection(s.state);
                  return (
                    <tr key={s.site}>
                      <td className="ellipsis">
                        <Link to={`/events?module=ogo&host=${encodeURIComponent(s.site)}`} className="mono">{s.site}</Link>
                      </td>
                      <td><span className={p.className}>{p.label}</span></td>
                      <td className="num">{formatNumber(s.traffic)}</td>
                      <td className="num">{formatNumber(s.blocked)}</td>
                      <td className="num">{formatNumber(s.banned)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          {(data.categories ?? []).length > 0 && (
            <p className="small muted">
              Attaques détectées : {data.categories!.slice(0, 5).map((c) => `${c.name} (${formatNumber(c.count)})`).join(", ")}
            </p>
          )}
        </>
      )}
    </Card>
  );
}

/** Adresses IP publiques : seules celles-ci peuvent avoir visé les sites web. */
export function isPublicIp(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/.exec(ip);
  if (!m) return ip.includes(":") && !/^(fe80|fc|fd|::1$)/i.test(ip);
  const [a, b] = [Number(m[1]), Number(m[2])];
  return !(a === 10 || a === 127 || a === 0 || a >= 224 || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127));
}

function OgoIp({ ip }: { ip: string }) {
  const { data, error } = usePolling(() => api<Activity>(`/ogo/ip/${encodeURIComponent(ip)}`), [ip], 0);
  if (error) return <li><span className="mono">{ip}</span> : <span className="muted">{error}</span></li>;
  if (!data) return <li><span className="mono">{ip}</span> : <span className="muted">interrogation d'OGO…</span></li>;
  if (data.error) return <li><span className="mono">{ip}</span> : <span className="muted">{data.error}</span></li>;
  const t = data.totals;
  if (!t || !t.traffic)
    return <li><span className="mono">{ip}</span> : aucune requête vers les sites protégés sur {data.days ?? 7} jours.</li>;
  return (
    <li>
      <span className="mono">{ip}</span> : <strong>{formatNumber(t.traffic)}</strong> requête(s) sur {data.days ?? 7} jours,{" "}
      <strong className={t.blocked ? "text-bad" : ""}>{formatNumber(t.blocked)}</strong> bloquée(s)
      {t.banned > 0 && <>, {formatNumber(t.banned)} après bannissement</>}
      {t.suspect > 0 && <>, {formatNumber(t.suspect)} suspecte(s)</>}
      <div className="small muted">
        Sites visés : {(data.sites ?? []).slice(0, 5).map((s) => `${s.site} (${formatNumber(s.traffic)})`).join(", ") || "?"}
        {(data.categories ?? []).length > 0 && <> · attaques : {data.categories!.slice(0, 4).map((c) => c.name).join(", ")}</>}
      </div>
    </li>
  );
}

/** Détail d'une alerte : ces adresses ont-elles aussi visé les sites web protégés par OGO ? */
export function OgoSeen({ ips }: { ips: string[] }) {
  const candidates = [...new Set(ips.filter(isPublicIp))].slice(0, 5);
  const { data } = usePolling(() => api<Activity>("/ogo/summary"), [], 0);
  if (!candidates.length || !data?.enabled) return null;
  return (
    <Card title="Vu par OGO (sites web)" icon={Globe}>
      <ul className="ogo-seen">
        {candidates.map((ip) => <OgoIp key={ip} ip={ip} />)}
      </ul>
      <p className="muted small">
        Requêtes de ces adresses vers les sites protégés par OGO sur 7 jours, lues dans OGO à l'ouverture de l'alerte
        (mises en cache 10 minutes). Une adresse qui attaque aussi les sites web relève d'une campagne ciblée.
      </p>
    </Card>
  );
}
