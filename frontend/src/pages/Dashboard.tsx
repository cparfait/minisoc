import { useState, type ReactNode } from "react";
import {
  Activity, BellRing, Crosshair, Flame, Globe2, LayoutDashboard, ListOrdered, OctagonAlert, Server, Settings2, Siren,
  TrendingUp, TriangleAlert, type LucideIcon,
} from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { api, query } from "../api";
import CountryBars from "../components/CountryBars";
import { HourlyBars, TrendChart } from "../components/charts";
import { DashboardCustomizer, useDashboardLayout, type WidgetDef, type WidgetSetting } from "../components/DashboardLayout";
import ExposureTop from "../components/Exposure";
import { PriorityPill } from "../components/Priority";
import { RiskTop } from "../components/Risk";
import M365Activity from "../components/M365Activity";
import VpnActivity from "../components/VpnActivity";
import CyberwatchExposure from "../components/CyberwatchExposure";
import ParcExposure from "../components/ParcExposure";
import { AlertsByTool, CertFr, KevOnFleet, MyAlerts, OpenIncidents, OverdueAlerts } from "../components/DashboardWidgets";
import { Card, Empty, ErrorBanner, PageHeader, SeverityBadge } from "../components/ui";
import { usePolling } from "../hooks";
import { SEVERITY_LABEL, formatNumber, formatShort, moduleLabel, timeAgo } from "../labels";
import type { Alert, Overview, Severity } from "../types";

const KPI: { sev: Severity; icon: LucideIcon }[] = [
  { sev: "critical", icon: OctagonAlert },
  { sev: "high", icon: Flame },
  { sev: "medium", icon: TriangleAlert },
];

const SORT_KEY = "minisoc.alerts.sort";

const lines = (values: number[], fallback: number) => ({
  key: "lines",
  label: "Lignes",
  values: values.map((v) => ({ value: v, label: String(v) })),
  default: fallback,
});

/** Cartes disponibles, dans l'ordre et à l'emplacement par défaut. */
const WIDGETS: WidgetDef[] = [
  { id: "kpis", title: "Compteurs d'alertes", description: "Alertes ouvertes par sévérité, nouvelles alertes sur 24 h.", zone: "top" },
  { id: "sources", title: "État des sources", description: "Dernier message reçu de chaque source.", zone: "top" },
  {
    id: "alerts",
    title: "Alertes (priorité / plus récentes)",
    description: "Alertes ouvertes, par priorité ou par activité la plus récente.",
    zone: "left",
    options: [lines([5, 8, 12, 20], 8)],
  },
  { id: "auth_hourly", title: "Échecs d'authentification par heure", description: "Courbe sur 24 h, cliquable.", zone: "left" },
  { id: "risk", title: "Machines et comptes à risque", description: "Score de risque cumulé sur 7 jours.", zone: "left", options: [lines([5, 8, 15], 8)] },
  { id: "countries", title: "Origine des échecs (pays)", description: "Pays des échecs d'authentification sur 24 h.", zone: "left" },
  { id: "trend", title: "Alertes créées (30 jours)", description: "Histogramme par jour et par sévérité.", zone: "left" },
  {
    id: "vpn",
    title: "Accès VPN et administration du pare-feu",
    description: "Échecs et connexions depuis l'étranger, sur 24 h.",
    zone: "right",
    options: [lines([6, 12, 20], 12)],
  },
  {
    id: "m365",
    title: "Comptes Microsoft 365",
    description: "Connexions, échecs par motif, comptes visés, connexions depuis l'étranger et changements sensibles, sur 24 h.",
    zone: "right",
    options: [lines([5, 10, 20], 10)],
  },
  { id: "top_ips", title: "Adresses les plus actives en échec", description: "Classement sur 24 h.", zone: "right", options: [lines([5, 10], 10)] },
  { id: "exposure", title: "À corriger en priorité", description: "Machines les plus exposées (vulnérabilités, alertes, criticité).", zone: "right", options: [lines([5, 8, 15], 8)] },
  { id: "rules", title: "Règles les plus déclenchées", description: "Sur les alertes ouvertes.", zone: "right" },
  { id: "volumes", title: "Événements reçus par source", description: "Volumes sur 24 h.", zone: "right" },
  // Cartes supplémentaires, masquées par défaut : à afficher depuis « Personnaliser »
  { id: "mine", title: "Mes alertes", description: "Alertes ouvertes qui vous sont assignées.", zone: "left", hidden: true, options: [lines([5, 8, 12], 8)] },
  { id: "overdue", title: "Alertes en retard", description: "En retard sur l'échéance de prise en charge ou de traitement.", zone: "left", hidden: true, options: [lines([5, 8, 12], 8)] },
  { id: "incidents", title: "Incidents en cours", description: "Incidents ouverts, en investigation ou contenus.", zone: "left", hidden: true, options: [lines([5, 8, 12], 8)] },
  { id: "by_tool", title: "Alertes ouvertes par outil", description: "Répartition par outil d'origine.", zone: "right", hidden: true },
  { id: "kev", title: "Failles KEV présentes sur le parc", description: "CVE activement exploitées présentes (Cyberwatch).", zone: "right", hidden: true, options: [lines([5, 8, 15], 8)] },
  { id: "cyberwatch", title: "Vulnérabilités : actifs les plus exposés", description: "Synthèse Cyberwatch (failles KEV, prioritaires, fin de support).", zone: "right", hidden: true },
  { id: "ninjaone", title: "Parc : postes les plus exposés (NinjaOne)", description: "Vulnérabilités, antivirus, menaces (NinjaOne).", zone: "right", hidden: true },
  { id: "certfr", title: "CERT-FR : dernières publications", description: "Alertes et avis récents du CERT-FR.", zone: "right", hidden: true, options: [lines([4, 6, 10], 6)] },
];

export default function Dashboard() {
  const navigate = useNavigate();
  const { layout, update, reset } = useDashboardLayout(WIDGETS);
  const [editing, setEditing] = useState(false);
  const overview = usePolling(() => api<Overview>("/stats/overview"), [], 15000);
  // Même choix que la liste des alertes (« Par priorité » / « Plus récentes »), mémorisé sur ce poste
  const [order, setOrder] = useState(() => localStorage.getItem(SORT_KEY) || "priority");
  const chooseOrder = (value: string) => {
    localStorage.setItem(SORT_KEY, value);
    setOrder(value);
  };
  const alertLines = Number(layout.widgets.find((w) => w.id === "alerts")?.options.lines ?? 8);
  const recent = usePolling(
    () => api<{ items: Alert[] }>(`/alerts${query({ status: "new,in_progress,waiting", sort: order, limit: alertLines })}`),
    [order, alertLines],
    15000,
  );
  const o = overview.data;

  const render = (w: WidgetSetting): ReactNode => {
    const n = Number(w.options.lines ?? 0) || undefined;
    switch (w.id) {
      case "kpis":
        return (
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
        );
      case "sources":
        return (
          <Card title="État des sources" icon={Server}>
            {o && o.sources.length ? (
              <div className="sources-strip">
                {[...o.sources]
                  .sort((a, b) => Number(b.status === "silent") - Number(a.status === "silent"))
                  .map((s) => (
                    <Link
                      to="/integrations"
                      key={s.module}
                      className={`source-pill source-${s.status}`}
                      title={
                        s.status === "silent"
                          ? `Plus aucune donnée depuis ${timeAgo(s.last_seen).replace("il y a ", "")} (seuil ${s.max_silence_minutes} min) : vérifier l'envoi`
                          : s.status === "unknown"
                            ? "Aucune donnée reçue depuis l'activation"
                            : `Dernière donnée ${timeAgo(s.last_seen)}`
                      }
                    >
                      <i />
                      {moduleLabel(s.module)}
                      <small>
                        {s.status === "silent" ? `muette · ${timeAgo(s.last_seen)}` : s.status === "unknown" ? "en attente" : timeAgo(s.last_seen)}
                      </small>
                    </Link>
                  ))}
              </div>
            ) : (
              <Empty>Aucune source n'a encore envoyé d'événement.</Empty>
            )}
          </Card>
        );
      case "alerts":
        return (
          <Card title={order === "recent" ? "Dernières alertes" : "À traiter en priorité"} icon={Siren}>
            <div className="sort-toggle card-toggle" role="group" aria-label="Ordre des alertes">
              <button type="button" className={order === "priority" ? "active" : ""} onClick={() => chooseOrder("priority")}>
                Par priorité
              </button>
              <button type="button" className={order === "recent" ? "active" : ""} onClick={() => chooseOrder("recent")}>
                Plus récentes
              </button>
            </div>
            {recent.data?.items.length ? (
              <>
                <ul className="alert-list">
                  {recent.data.items.map((a) => (
                    <li key={a.id}>
                      <PriorityPill score={a.priority} reasons={a.priority_reasons} />
                      <SeverityBadge severity={a.severity} />
                      <Link to={`/alerts/${a.id}`}>{a.title}</Link>
                      <small title={`Première détection : ${formatShort(a.first_seen)}`}>{timeAgo(a.last_seen)}</small>
                    </li>
                  ))}
                </ul>
                <Link to={`/alerts?sort=${order}`} className="small">
                  {order === "recent" ? "Toutes les alertes, plus récentes d'abord" : "Toute la file, par priorité"}
                </Link>
              </>
            ) : (
              <Empty>Aucune alerte ouverte.</Empty>
            )}
          </Card>
        );
      case "auth_hourly":
        return (
          <Card title="Échecs d'authentification (24 h)" icon={Activity}>
            {o && (
              <HourlyBars
                points={o.auth_failures_hourly}
                onSelect={(hour) =>
                  navigate(
                    hour
                      ? `/events?category=authentication&outcome=failure&from=${encodeURIComponent(hour.toISOString())}&to=${encodeURIComponent(new Date(hour.getTime() + 3600000).toISOString())}`
                      : "/events?category=authentication&outcome=failure&period=24h",
                  )
                }
              />
            )}
          </Card>
        );
      case "risk":
        return <RiskTop limit={n} />;
      case "countries":
        return o && o.failures_by_country?.length > 0 ? (
          <Card title="Origine des échecs d'authentification (24 h)" icon={Globe2}>
            <CountryBars rows={o.failures_by_country} />
            <p className="muted small attribution">Géolocalisation : GeoLite2 de MaxMind (https://www.maxmind.com).</p>
          </Card>
        ) : null;
      case "trend":
        return <Card title="Alertes créées (30 jours)" icon={TrendingUp}>{o && <TrendChart trend={o.trend} />}</Card>;
      case "vpn":
        return <VpnActivity rows={n} />;
      case "m365":
        return <M365Activity rows={n} />;
      case "top_ips":
        return (
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
                  {o.top_attackers.slice(0, n).map((a) => (
                    <tr key={a.ip}>
                      <td className="nowrap" title={a.asn ?? ""}>
                        <Link to={`/events?ip=${encodeURIComponent(a.ip)}`} className="mono">
                          {a.ip}
                        </Link>
                        {a.name && <span className="host-name">{a.name}</span>}
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
        );
      case "exposure":
        return <ExposureTop limit={n} />;
      case "rules":
        return (
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
        );
      case "volumes":
        return (
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
        );
      case "mine":
        return <MyAlerts lines={n} />;
      case "overdue":
        return <OverdueAlerts lines={n} />;
      case "incidents":
        return <OpenIncidents lines={n} />;
      case "by_tool":
        return <AlertsByTool />;
      case "kev":
        return <KevOnFleet lines={n} />;
      case "cyberwatch":
        return <CyberwatchExposure />;
      case "ninjaone":
        return <ParcExposure />;
      case "certfr":
        return <CertFr lines={n} />;
      default:
        return null;
    }
  };

  const zone = (z: "top" | "left" | "right") =>
    layout.widgets.filter((w) => w.zone === z && !w.hidden).map((w) => {
      const content = render(w);
      return content ? <div key={w.id} className="dash-widget">{content}</div> : null;
    });

  return (
    <>
      <PageHeader title="Tableau de bord" icon={LayoutDashboard} subtitle="Vue d'ensemble de la sécurité, en temps réel">
        <button type="button" className={editing ? "primary" : ""} onClick={() => setEditing(!editing)}>
          <Settings2 size={15} /> Personnaliser
        </button>
      </PageHeader>
      <ErrorBanner error={overview.error} />
      {o?.clickhouse_error && <ErrorBanner error="Base des événements indisponible : graphiques incomplets." />}
      {editing && (
        <DashboardCustomizer defs={WIDGETS} layout={layout} onChange={update} onReset={reset} onClose={() => setEditing(false)} />
      )}

      <div className="dash-top">{zone("top")}</div>
      {/* Deux colonnes indépendantes : chaque carte garde sa hauteur, sans vide sous les cartes courtes */}
      <div className="dash-cols">
        <div className="dash-col">{zone("left")}</div>
        <div className="dash-col">{zone("right")}</div>
      </div>
    </>
  );
}
