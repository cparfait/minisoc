import {
  Activity, BellRing, Crosshair, Flame, Globe2, LayoutDashboard, ListOrdered, OctagonAlert, Server, Siren, TrendingUp,
  TriangleAlert, type LucideIcon,
} from "lucide-react";
import { Link } from "react-router-dom";
import { api, query } from "../api";
import CountryBars from "../components/CountryBars";
import { HourlyBars, TrendChart } from "../components/charts";
import ExposureTop from "../components/Exposure";
import { PriorityPill } from "../components/Priority";
import { RiskTop } from "../components/Risk";
import { Card, Empty, ErrorBanner, PageHeader, SeverityBadge } from "../components/ui";
import { usePolling } from "../hooks";
import { SEVERITY_LABEL, formatNumber, moduleLabel, timeAgo } from "../labels";
import type { Alert, Overview, Severity } from "../types";

const KPI: { sev: Severity; icon: LucideIcon }[] = [
  { sev: "critical", icon: OctagonAlert },
  { sev: "high", icon: Flame },
  { sev: "medium", icon: TriangleAlert },
];

export default function Dashboard() {
  const overview = usePolling(() => api<Overview>("/stats/overview"), [], 15000);
  const recent = usePolling(
    () => api<{ items: Alert[] }>(`/alerts${query({ status: "new,in_progress,waiting", sort: "priority", limit: 8 })}`),
    [],
    15000,
  );
  const o = overview.data;

  return (
    <>
      <PageHeader title="Tableau de bord" icon={LayoutDashboard} subtitle="Vue d'ensemble de la sécurité, en temps réel" />
      <ErrorBanner error={overview.error} />
      {o?.clickhouse_error && <ErrorBanner error="Base des événements indisponible : graphiques incomplets." />}

      <div className="kpis">
        {KPI.map(({ sev, icon: Icon }) => (
          <Link key={sev} to={`/alerts?severity_min=${sev}`} className={`kpi kpi-${sev}`}>
            <span className="kpi-head">
              {SEVERITY_LABEL[sev]}s
              <span className="kpi-icon">
                <Icon size={18} />
              </span>
            </span>
            <span className="kpi-value">{o ? o.open_by_severity[sev] : "–"}</span>
            <span className="kpi-label">alertes ouvertes</span>
          </Link>
        ))}
        <Link to="/alerts?period=24h&status=" className="kpi kpi-new">
          <span className="kpi-head">
            Dernières 24 h
            <span className="kpi-icon">
              <BellRing size={18} />
            </span>
          </span>
          <span className="kpi-value">{o ? o.new_24h : "–"}</span>
          <span className="kpi-label">nouvelles alertes</span>
        </Link>
      </div>

      <Card title="État des sources" icon={Server}>
        {o && o.sources.length ? (
          <div className="sources-strip">
            {o.sources.map((s) => (
              <Link to="/integrations" key={s.module} className={`source-pill source-${s.status}`}>
                <i />
                {moduleLabel(s.module)}
                <small>{timeAgo(s.last_seen)}</small>
              </Link>
            ))}
          </div>
        ) : (
          <Empty>Aucune source n'a encore envoyé d'événement.</Empty>
        )}
      </Card>

      <div className="grid-2">
        <RiskTop />
        <ExposureTop />
      </div>

      <div className="grid-2">
        <Card title="À traiter en priorité" icon={Siren}>
          {recent.data?.items.length ? (
            <>
              <ul className="alert-list">
                {recent.data.items.map((a) => (
                  <li key={a.id}>
                    <PriorityPill score={a.priority} reasons={a.priority_reasons} />
                    <SeverityBadge severity={a.severity} />
                    <Link to={`/alerts/${a.id}`}>{a.title}</Link>
                    <small>{timeAgo(a.last_seen)}</small>
                  </li>
                ))}
              </ul>
              <Link to="/alerts" className="small">Toute la file, par priorité</Link>
            </>
          ) : (
            <Empty>Aucune alerte ouverte.</Empty>
          )}
        </Card>
        <Card title="Échecs d'authentification (24 h)" icon={Activity}>
          {o && <HourlyBars points={o.auth_failures_hourly} />}
        </Card>
      </div>

      <div className="grid-2">
        <Card title="IP les plus actives en échec d'authentification (24 h)" icon={Crosshair}>
          {o?.top_attackers.length ? (
            <table>
              <thead>
                <tr>
                  <th>Adresse IP</th>
                  <th className="num">Échecs</th>
                  <th className="num">Comptes visés</th>
                  <th>Exemples</th>
                </tr>
              </thead>
              <tbody>
                {o.top_attackers.map((a) => (
                  <tr key={a.ip}>
                    <td className="nowrap" title={a.asn ?? ""}>
                      <Link to={`/events?ip=${encodeURIComponent(a.ip)}`} className="mono">
                        {a.ip}
                      </Link>
                      {a.country && <span className="geo-tag">{a.country}</span>}
                      {a.intel && <span className="intel-tag" title={a.intel}>banni</span>}
                    </td>
                    <td className="num">{formatNumber(a.failures)}</td>
                    <td className="num">{a.users}</td>
                    <td className="muted ellipsis">{a.sample_users.filter(Boolean).join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>Aucun échec d'authentification sur 24 h.</Empty>
          )}
        </Card>
        <Card title="Alertes créées (30 jours)" icon={TrendingUp}>{o && <TrendChart trend={o.trend} />}</Card>
      </div>

      {o && o.failures_by_country?.length > 0 && (
        <Card title="Origine des échecs d'authentification (24 h)" icon={Globe2}>
          <CountryBars rows={o.failures_by_country} />
          <p className="muted small attribution">Géolocalisation : GeoLite2 de MaxMind (https://www.maxmind.com).</p>
        </Card>
      )}

      <div className="grid-2">
        <Card title="Règles les plus déclenchées (alertes ouvertes)" icon={ListOrdered}>
          {o?.top_rules.length ? (
            <table>
              <tbody>
                {o.top_rules.map((r) => (
                  <tr key={r.rule_id}>
                    <td className="mono">{r.rule_id}</td>
                    <td>
                      <Link to={`/alerts?rule_id=${encodeURIComponent(r.rule_id)}`}>{r.rule_name}</Link>
                    </td>
                    <td className="num">{r.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>Aucune alerte ouverte.</Empty>
          )}
        </Card>
        <Card title="Événements reçus par source (24 h)" icon={Server}>
          {o?.events_by_module.length ? (
            <table>
              <tbody>
                {o.events_by_module.map((m) => (
                  <tr key={m.module}>
                    <td>{moduleLabel(m.module)}</td>
                    <td className="num">{formatNumber(m.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>Aucun événement reçu sur 24 h.</Empty>
          )}
        </Card>
      </div>
    </>
  );
}
