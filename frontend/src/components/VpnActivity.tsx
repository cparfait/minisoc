import { KeyRound } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { usePolling } from "../hooks";
import { formatNumber, timeAgo } from "../labels";
import { Card, Empty } from "./ui";

interface VpnStats {
  summary: { failures?: number; successes?: number; users_failed?: number; ips_failed?: number; masked?: number; successes_abroad?: number };
  services: { service: string; failures: number; successes: number; users_failed: number }[];
  targeted: { user: string; failures: number }[];
  recent: { ts: string; service: string; user: string; ip: string; country: string; outcome: string; reason: string; name?: string }[];
  home_countries?: string[];
  clickhouse_error?: boolean;
}

export const SERVICE_LABEL: Record<string, string> = {
  ssl_vpn: "VPN SSL",
  ipsec: "VPN IPsec",
  l2tp: "L2TP",
  user_portal: "Portail VPN",
  admin_console: "Administration",
};

const REASON: Record<string, string> = {
  invalid_credentials: "mauvais mot de passe",
  unknown_user: "compte inconnu",
  account_locked: "compte verrouillé",
  account_disabled: "compte désactivé",
  password_expired: "mot de passe expiré",
  mfa_failed: "MFA refusé",
  outside_hours: "hors plage horaire",
};

/** Accès distants au pare-feu (VPN, portail VPN, administration) sur 24 h : sans défilement, en haut du tableau de bord. */
export default function VpnActivity({ rows = 12 }: { rows?: number }) {
  const { data } = usePolling(() => api<VpnStats>(`/stats/vpn?recent=${rows}`), [rows], 30000);
  const s = data?.summary ?? {};
  const hasData = (s.failures ?? 0) + (s.successes ?? 0) > 0;
  const home = data?.home_countries ?? ["FR"];
  const homeLabel = home.length === 1 && home[0] === "FR" ? "France" : home.join(", ");
  return (
    <Card title="Accès VPN et administration du pare-feu (24 h)" icon={KeyRound} className="vpn-card">
      {!data ? null : !hasData ? (
        <Empty>Aucune authentification VPN reçue sur 24 h (journaux du Sophos XGS).</Empty>
      ) : (
        <>
          <div className="vpn-kpis">
            <Link to="/events?module=sophos_xgs&outcome=failure&period=24h" className={`vpn-kpi ${s.failures ? "bad" : ""}`}>
              <strong>{formatNumber(s.failures ?? 0)}</strong>
              <span>échecs</span>
            </Link>
            <div className="vpn-kpi">
              <strong>{s.users_failed ?? 0}</strong>
              <span>comptes visés</span>
            </div>
            <div className="vpn-kpi">
              <strong>{s.ips_failed ?? 0}</strong>
              <span>adresses en échec</span>
            </div>
            <Link
              to="/events?module=sophos_xgs&category=authentication&outcome=success&period=24h"
              className={`vpn-kpi ${s.successes_abroad ? "bad" : "good"}`}
              title={`${formatNumber(s.successes ?? 0)} connexion(s) réussie(s) au total`}
            >
              <strong>{formatNumber(s.successes_abroad ?? 0)}</strong>
              <span>réussies hors de {homeLabel}</span>
            </Link>
          </div>
          {(s.masked ?? 0) > 0 && (
            <p className="muted small vpn-note">
              {formatNumber(s.masked ?? 0)} échec(s) sans adresse réelle (127.0.0.1 : portail VPN et VPN SSL sur le même port du pare-feu).
            </p>
          )}
          <div className="vpn-services">
            {data.services.map((x) => (
              <span key={x.service} className={`vpn-service ${x.failures > 20 ? "bad" : ""}`} title={`${x.users_failed} compte(s) en échec`}>
                {SERVICE_LABEL[x.service] ?? x.service} <b>{x.failures}</b> échec(s) · <b>{x.successes}</b> réussie(s)
              </span>
            ))}
          </div>
          {data.targeted.length > 0 && (
            <p className="small vpn-targeted">
              <span className="muted">Comptes les plus visés : </span>
              {data.targeted.map((t, i) => (
                <span key={t.user}>
                  {i > 0 && ", "}
                  <Link to={`/events?user=${encodeURIComponent(t.user)}&module=sophos_xgs`}>{t.user}</Link>
                  <span className="muted"> ({t.failures})</span>
                </span>
              ))}
            </p>
          )}
          <p className="small muted vpn-list-title">
            À regarder : échecs et connexions réussies hors de {homeLabel} ({formatNumber(s.successes ?? 0)} connexion(s) réussie(s) au total, non listées).
          </p>
          {data.recent.length === 0 && <Empty>Aucun échec ni connexion depuis l'étranger sur 24 h.</Empty>}
          <table className="vpn-recent">
            <tbody>
              {data.recent.map((r, i) => (
                <tr key={`${r.ts}-${i}`} className={r.outcome === "failure" ? "fail" : "ok"}>
                  <td className="nowrap muted small">{timeAgo(r.ts)}</td>
                  <td className="nowrap">
                    <span className={`vpn-dot ${r.outcome === "failure" ? "bad" : "good"}`} />
                    {SERVICE_LABEL[r.service] ?? r.service}
                  </td>
                  <td className="ellipsis">
                    <Link to={`/events?user=${encodeURIComponent(r.user)}&module=sophos_xgs`}>{r.user || "—"}</Link>
                  </td>
                  <td className="nowrap mono small">
                    {r.ip.startsWith("127.") ? <span className="muted" title="Adresse masquée par le pare-feu">masquée</span> : (
                      <Link to={`/events?ip=${encodeURIComponent(r.ip)}`} title={r.name ? `${r.name} (${r.ip})` : r.ip}>
                        {r.name || r.ip}
                      </Link>
                    )}
                    {r.country && <span className="geo-tag">{r.country}</span>}
                  </td>
                  <td className={`small ellipsis ${r.outcome === "failure" ? "muted" : "text-bad"}`}>
                    {r.outcome === "failure" ? REASON[r.reason] ?? "échec" : "réussie depuis l'étranger"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </Card>
  );
}
