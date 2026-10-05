import { FileChartColumn } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useUser } from "../App";
import CountryBars from "../components/CountryBars";
import { Card, ErrorBanner, PageHeader } from "../components/ui";
import { usePolling } from "../hooks";
import { SEVERITY_LABEL, formatNumber, moduleLabel } from "../labels";
import type { Severity } from "../types";
import Archives from "../components/Archives";

interface Stat {
  count: number;
  median: number | null;
  p90: number | null;
}
interface Report {
  month: string;
  label: string;
  events: { total: number; by_module: { module: string; count: number }[]; error: string };
  alerts: {
    total: number;
    previous_total: number;
    by_severity: Record<Severity, number>;
    by_status: Record<string, number>;
    by_module: { module: string; count: number }[];
    top_rules: { rule_id: string; name: string; count: number }[];
    verdicts: Record<string, number>;
    false_positive_rate: number | null;
    still_open: number;
    open_now: number;
    time_to_acknowledge_min: Stat;
    time_to_close_min: Stat;
  };
  incidents: {
    opened: number;
    closed: number;
    items: { id: number; title: string; status: string; severity: Severity; category: string; personal_data: boolean }[];
  };
  blocks: number;
  auth: {
    failures: number;
    successes: number;
    ips: number;
    users: number;
    countries: { country: string; failures: number; ips: number }[];
    top_attackers: { ip: string; failures: number; users: number; country: string; asn: string }[];
  };
}

const MONTHS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"];

function duration(minutes: number | null): string {
  if (minutes === null) return "—";
  if (minutes < 60) return `${minutes} min`;
  if (minutes < 48 * 60) return `${(minutes / 60).toFixed(1).replace(".", ",")} h`;
  return `${(minutes / 1440).toFixed(1).replace(".", ",")} j`;
}

function trend(current: number, previous: number): string {
  if (!previous) return current ? "mois précédent sans alerte" : "";
  const delta = Math.round((100 * (current - previous)) / previous);
  return `${delta >= 0 ? "+" : ""}${delta} % vs mois précédent (${previous})`;
}

/** Les 13 derniers mois (le mois en cours est partiel). */
function monthChoices(): { value: string; label: string }[] {
  const now = new Date();
  return Array.from({ length: 13 }, (_, i) => {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const value = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
    return { value, label: `${MONTHS[d.getMonth()]} ${d.getFullYear()}${i === 0 ? " (en cours)" : ""}` };
  });
}

export default function Reports() {
  const user = useUser();
  const choices = useMemo(monthChoices, []);
  const [params, setParams] = useSearchParams();
  const month = params.get("month") ?? choices[1].value;
  const { data, error } = usePolling(() => api<Report>(`/reports/monthly?month=${month}`), [month], 300000);
  const [sending, setSending] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const download = async () => {
    const res = await fetch(`/api/reports/monthly.md?month=${month}`, { credentials: "same-origin" });
    if (!res.ok) return setMessage({ ok: false, text: `Téléchargement impossible (HTTP ${res.status})` });
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = `rapport-securite-${month}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };
  const send = async () => {
    setSending(true);
    setMessage(null);
    try {
      const r = await api<{ sent_to: string[] }>(`/admin/reports/monthly/send?month=${month}`, { method: "POST" });
      setMessage({ ok: true, text: `Envoyé à ${r.sent_to.join(", ")}` });
    } catch (e) {
      setMessage({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setSending(false);
    }
  };

  const a = data?.alerts;
  return (
    <>
      <PageHeader title="Rapport mensuel" icon={FileChartColumn} subtitle="Activité de sécurité du mois, pour la direction">
        <select value={month} onChange={(e) => setParams({ month: e.target.value })} aria-label="Mois">
          {choices.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </select>
        <button type="button" onClick={download}>
          Télécharger (.md)
        </button>
        {user?.role === "admin" && (
          <button type="button" disabled={sending} onClick={send}>
            {sending ? "Envoi…" : "Envoyer par e-mail"}
          </button>
        )}
      </PageHeader>
      <p className="muted">
        Activité de sécurité du mois, pour la direction et le suivi dans le temps. Envoyé automatiquement le 1er du mois
        (Paramètres › Notifications).
      </p>
      <ErrorBanner error={error} />
      {message && <p className={message.ok ? "text-good" : "text-bad"}>{message.text}</p>}
      {data && a && (
        <>
          <div className="report-tiles">
            <div className="report-tile">
              <strong>{formatNumber(a.total)}</strong>
              <span>alertes</span>
              <small className="muted">{trend(a.total, a.previous_total)}</small>
            </div>
            <div className="report-tile">
              <strong>{data.incidents.opened}</strong>
              <span>incident(s) ouvert(s)</span>
              <small className="muted">{data.incidents.closed} clos dans le mois</small>
            </div>
            <div className="report-tile">
              <strong>{duration(a.time_to_acknowledge_min.median)}</strong>
              <span>prise en charge (médiane)</span>
              <small className="muted">90 % en moins de {duration(a.time_to_acknowledge_min.p90)}</small>
            </div>
            <div className="report-tile">
              <strong>{duration(a.time_to_close_min.median)}</strong>
              <span>clôture (médiane)</span>
              <small className="muted">
                {a.false_positive_rate !== null ? `${a.false_positive_rate} % de faux positifs` : ""}
              </small>
            </div>
            <div className="report-tile">
              <strong>{a.still_open}</strong>
              <span>alertes du mois encore ouvertes</span>
              <small className="muted">{a.open_now} toutes périodes</small>
            </div>
            <div className="report-tile">
              <strong>{data.blocks}</strong>
              <span>blocage(s) d'IP</span>
              <small className="muted">{formatNumber(data.events.total)} événements collectés</small>
            </div>
          </div>

          <div className="grid-2">
            <Card title="Alertes par sévérité">
              <ul className="report-bars">
                {(Object.entries(a.by_severity) as [Severity, number][]).map(([sev, n]) => (
                  <li key={sev}>
                    <span className={`badge sev-${sev}`}>{SEVERITY_LABEL[sev]}</span>
                    <span className="report-track">
                      <span className={`report-fill sev-bg-${sev}`} style={{ width: `${(n / Math.max(1, a.total)) * 100}%` }} />
                    </span>
                    <span className="num">{formatNumber(n)}</span>
                  </li>
                ))}
              </ul>
              {Object.keys(a.verdicts).length > 0 && (
                <p className="muted small">
                  Qualification automatique : {Object.entries(a.verdicts).map(([k, v]) => `${k} ${v}`).join(", ")}.
                </p>
              )}
            </Card>
            <Card title="Règles les plus actives">
              <table>
                <tbody>
                  {a.top_rules.map((r) => (
                    <tr key={r.rule_id}>
                      <td>
                        <Link to={`/alerts?status=&rule_id=${encodeURIComponent(r.rule_id)}`}>{r.rule_id}</Link> {r.name}
                      </td>
                      <td className="num">{formatNumber(r.count)}</td>
                    </tr>
                  ))}
                  {!a.top_rules.length && (
                    <tr>
                      <td className="muted">Aucune alerte ce mois-ci.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </Card>
          </div>

          <div className="grid-2">
            <Card title={`Incidents ouverts dans le mois (${data.incidents.opened})`}>
              {data.incidents.items.length ? (
                <ul className="plain-list">
                  {data.incidents.items.map((i) => (
                    <li key={i.id}>
                      <Link to={`/incidents/${i.id}`}>
                        n° {i.id} · {i.title}
                      </Link>{" "}
                      <span className="muted small">
                        ({SEVERITY_LABEL[i.severity]}, {i.status}
                        {i.personal_data ? ", données personnelles" : ""})
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="muted">Aucun incident.</p>
              )}
            </Card>
            <Card title="Alertes et volume par source">
              <table>
                <thead>
                  <tr>
                    <th>Source</th>
                    <th className="num">Alertes</th>
                    <th className="num">Événements</th>
                  </tr>
                </thead>
                <tbody>
                  {[...new Set([...a.by_module.map((m) => m.module), ...data.events.by_module.map((m) => m.module)])].map((m) => (
                    <tr key={m}>
                      <td>{moduleLabel(m)}</td>
                      <td className="num">{formatNumber(a.by_module.find((x) => x.module === m)?.count ?? 0)}</td>
                      <td className="num">{formatNumber(data.events.by_module.find((x) => x.module === m)?.count ?? 0)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {data.events.error && <p className="text-bad small">{data.events.error}</p>}
            </Card>
          </div>

          <div className="grid-2">
            <Card title="Attaques d'authentification">
              <p>
                <strong>{formatNumber(data.auth.failures)}</strong> échecs depuis <strong>{formatNumber(data.auth.ips)}</strong>{" "}
                adresses, visant <strong>{formatNumber(data.auth.users)}</strong> comptes.
              </p>
              <table>
                <thead>
                  <tr>
                    <th>Adresse</th>
                    <th>Pays</th>
                    <th>Opérateur</th>
                    <th className="num">Échecs</th>
                    <th className="num">Comptes</th>
                  </tr>
                </thead>
                <tbody>
                  {data.auth.top_attackers.map((x) => (
                    <tr key={x.ip}>
                      <td className="mono">
                        <Link to={`/events?ip=${encodeURIComponent(x.ip)}&period=30d`}>{x.ip}</Link>
                      </td>
                      <td>{x.country || "?"}</td>
                      <td className="small ellipsis">{x.asn || "?"}</td>
                      <td className="num">{formatNumber(x.failures)}</td>
                      <td className="num">{x.users}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
            <Card title="Échecs par pays">
              {data.auth.countries.length ? <CountryBars rows={data.auth.countries} /> : <p className="muted">Aucune donnée.</p>}
            </Card>
          </div>
        </>
      )}
      <Archives />
    </>
  );
}
