import { UserCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { usePolling } from "../hooks";
import { formatNumber, timeAgo } from "../labels";
import { Card, Empty } from "./ui";

interface M365Stats {
  enabled?: boolean;
  summary: {
    failures?: number;
    successes?: number;
    users_ok?: number;
    users_failed?: number;
    ips_failed?: number;
    mfa_failed?: number;
    successes_abroad?: number;
    users_abroad?: number;
  };
  reasons: { reason: string; n: number; users?: number }[];
  targeted: { user: string; failures: number; countries: number }[];
  recent: { ts: string; user: string; ip: string; country: string; outcome: string; reason: string }[];
  changes: { ts: string; action: string; user: string; what: string; detail: string }[];
  home_countries?: string[];
  clickhouse_error?: boolean;
}

const REASON: Record<string, string> = {
  invalid_credentials: "mauvais mot de passe",
  unknown_user: "compte inconnu",
  account_locked: "compte verrouillé",
  account_disabled: "compte désactivé",
  password_expired: "mot de passe expiré",
  mfa_failed: "MFA refusée",
  blocked_by_policy: "bloquée (accès conditionnel)",
  other: "autre",
};

const CHANGE: Record<string, string> = {
  role_member_added: "Rôle d'administration attribué",
  mfa_disabled: "MFA désactivée",
  app_consent: "Consentement à une application",
  password_reset: "Mot de passe réinitialisé",
  mail_forwarding_rule: "Transfert de messagerie",
};

const userLink = (user: string) => `/events?user=${encodeURIComponent(user)}&module=m365&period=24h`;

/** Comptes Microsoft 365 / Entra ID sur 24 h : connexions, échecs, comptes visés, étranger, changements sensibles. */
export default function M365Activity({ rows = 10 }: { rows?: number }) {
  const { data } = usePolling(() => api<M365Stats>(`/stats/m365?recent=${rows}`), [rows], 60000);
  const s = data?.summary ?? {};
  const hasData = (s.failures ?? 0) + (s.successes ?? 0) > 0 || (data?.changes.length ?? 0) > 0;
  const home = data?.home_countries ?? ["FR"];
  const homeLabel = home.length === 1 && home[0] === "FR" ? "France" : home.join(", ");
  return (
    <Card title="Comptes Microsoft 365 (24 h)" icon={UserCheck} className="vpn-card">
      {!data ? null : !hasData ? (
        <Empty>
          {data.enabled === false ? (
            <>
              Intégration Microsoft 365 désactivée : <Link to="/integrations">Intégrations</Link>.
            </>
          ) : (
            "Aucune connexion Microsoft 365 reçue sur 24 h (délai de Microsoft : 30 min à quelques heures)."
          )}
        </Empty>
      ) : (
        <>
          <div className="vpn-kpis">
            <Link to="/events?module=m365&outcome=failure&period=24h" className={`vpn-kpi ${s.failures ? "bad" : ""}`}>
              <strong>{formatNumber(s.failures ?? 0)}</strong>
              <span>échecs ({s.users_failed ?? 0} comptes)</span>
            </Link>
            <Link to="/events?module=m365&outcome=success&period=24h" className="vpn-kpi" title={`${formatNumber(s.successes ?? 0)} connexion(s) réussie(s)`}>
              <strong>{s.users_ok ?? 0}</strong>
              <span>comptes connectés</span>
            </Link>
            <Link
              to="/events?module=m365&outcome=failure&reason=mfa_failed&period=24h"
              className={`vpn-kpi ${s.mfa_failed ? "bad" : ""}`}
              title="MFA refusée ou non réalisée : à rapprocher d'une fatigue MFA (UC-38)"
            >
              <strong>{s.mfa_failed ?? 0}</strong>
              <span>MFA refusées</span>
            </Link>
            <div className={`vpn-kpi ${s.successes_abroad ? "bad" : "good"}`} title={`${s.users_abroad ?? 0} compte(s) concerné(s)`}>
              <strong>{formatNumber(s.successes_abroad ?? 0)}</strong>
              <span>réussies hors de {homeLabel}</span>
            </div>
          </div>
          {data.reasons.length > 0 && (
            <div className="reason-list">
              <p className="small muted reason-title">Échecs par motif (cliquer pour les voir)</p>
              {data.reasons.map((r) => {
                const max = Math.max(...data.reasons.map((x) => x.n), 1);
                const alarm = r.reason === "mfa_failed" || r.reason === "account_locked";
                return (
                  <Link
                    key={r.reason}
                    to={`/events?module=m365&outcome=failure&reason=${encodeURIComponent(r.reason)}&period=24h`}
                    className={`reason-row ${alarm ? "alarm" : ""}`}
                    title={r.users === undefined ? undefined : `${formatNumber(r.n)} échec(s) sur ${r.users} compte(s) distinct(s)`}
                  >
                    <span className="reason-label">{REASON[r.reason] ?? r.reason}</span>
                    <span className="reason-bar">
                      <i style={{ width: `${Math.max(4, (100 * r.n) / max)}%` }} />
                    </span>
                    <span className="reason-count">
                      <b>{formatNumber(r.n)}</b> {r.n > 1 ? "échecs" : "échec"}
                    </span>
                    <span className="reason-users">
                      {r.users !== undefined && (
                        <>
                          · <b>{r.users}</b> {r.users > 1 ? "comptes" : "compte"}
                        </>
                      )}
                    </span>
                  </Link>
                );
              })}
            </div>
          )}
          {data.targeted.length > 0 && (
            <p className="small vpn-targeted">
              <span className="muted">Comptes les plus visés : </span>
              {data.targeted.map((t, i) => (
                <span key={t.user}>
                  {i > 0 && ", "}
                  <Link to={userLink(t.user)}>{t.user}</Link>
                  <span className="muted">
                    {" "}
                    ({t.failures}
                    {t.countries > 1 ? `, ${t.countries} pays` : ""})
                  </span>
                </span>
              ))}
            </p>
          )}
          {data.changes.length > 0 && (
            <>
              <p className="small muted vpn-list-title">Changements sensibles du tenant :</p>
              <table className="vpn-recent">
                <tbody>
                  {data.changes.map((c, i) => (
                    <tr key={`${c.ts}-${i}`} className="fail">
                      <td className="nowrap muted small">{timeAgo(c.ts)}</td>
                      <td className="nowrap">
                        <span className="vpn-dot bad" />
                        {CHANGE[c.action] ?? c.action}
                      </td>
                      <td className="ellipsis">
                        <Link to={userLink(c.user)}>{c.user || "—"}</Link>
                      </td>
                      <td className="small ellipsis muted" title={c.detail || c.what}>
                        {c.what}
                        {c.detail ? ` · ${c.detail}` : ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
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
                  <td className="ellipsis">
                    <span className={`vpn-dot ${r.outcome === "failure" ? "bad" : "good"}`} />
                    <Link to={userLink(r.user)}>{r.user || "—"}</Link>
                  </td>
                  <td className="nowrap mono small">
                    {r.ip ? <Link to={`/events?ip=${encodeURIComponent(r.ip)}`}>{r.ip}</Link> : "—"}
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
