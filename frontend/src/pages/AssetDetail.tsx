import { Activity, ArrowLeft, ExternalLink, Monitor, Search as SearchIcon, Server, Siren, User as UserIcon } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, query } from "../api";
import { canEdit, useUser } from "../App";
import { DetectionName, ToolBadge, detectionName } from "../components/AlertBits";
import { PriorityPill } from "../components/Priority";
import { RiskCard } from "../components/Risk";
import Timeline from "../components/Timeline";
import { Card, Empty, ErrorBanner, PageHeader, SeverityBadge, StatusBadge } from "../components/ui";
import { formatDate, formatNumber, timeAgo } from "../labels";
import type { Alert, AlertStatus } from "../types";

type Criticality = "low" | "normal" | "high" | "vital";
const CRITICALITY: { value: Criticality; label: string }[] = [
  { value: "vital", label: "Vitale" },
  { value: "high", label: "Haute" },
  { value: "normal", label: "Normale" },
  { value: "low", label: "Basse" },
];
const isServer = (name: string) => /^(srv|svr|serveur|dc|ad|fs|sql|web|app|mail|exch)[-_0-9]/i.test(name);

interface Asset {
  id: number;
  display_name: string;
  criticality: Criticality;
  owner: string;
  service: string;
  description: string;
  asset_type: string;
  source: string;
  reviewed: boolean;
  internet_exposed: boolean;
}

interface SearchResult {
  rows: Record<string, unknown>[];
  events: Record<string, unknown>[];
  total: number | null;
}

/** Fiche d'une machine ou d'un compte : inventaire, alertes, activité sur 30 jours, derniers événements. */
export default function AssetDetail() {
  const { kind = "host", name = "" } = useParams();
  const host = kind === "host";
  const user = useUser();
  const editable = canEdit(user);
  const [asset, setAsset] = useState<Asset | null | undefined>(undefined);
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [timeline, setTimeline] = useState<SearchResult | null>(null);
  const [events, setEvents] = useState<SearchResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ criticality: "normal" as Criticality, owner: "", service: "", description: "", internet_exposed: false });
  const [saved, setSaved] = useState<string | null>(null);
  // Condition de recherche exacte (guillemets : les noms peuvent contenir des caractères spéciaux)
  const quoted = name.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const condition = `${host ? "host.name" : "user.name"}="${quoted}"`;

  const load = useCallback(async () => {
    setError(null);
    try {
      const [lookup, list] = await Promise.all([
        api<{ asset: Asset | null }>(`/assets/lookup${query({ kind: host ? "host" : "account", name })}`),
        api<{ items: Alert[] }>(`/alerts${query({ [host ? "host" : "account"]: name, status: "", sort: "priority", limit: 100 })}`),
      ]);
      setAsset(lookup.asset);
      if (lookup.asset) {
        const a = lookup.asset;
        setForm({ criticality: a.criticality, owner: a.owner, service: a.service, description: a.description, internet_exposed: a.internet_exposed });
      }
      setAlerts(list.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
    // Activité : deux recherches (tracées dans le journal d'audit comme toute consultation de journaux)
    api<SearchResult>("/search", { method: "POST", body: { query: `${condition} | timeline by event.module`, period: "30d" } })
      .then(setTimeline)
      .catch(() => setTimeline(null));
    api<SearchResult>("/search", { method: "POST", body: { query: `${condition} | head 50`, period: "30d" } })
      .then(setEvents)
      .catch(() => setEvents(null));
  }, [condition, host, name]);

  useEffect(() => {
    load();
  }, [load]);

  const save = async () => {
    setSaved(null);
    try {
      if (asset) {
        await api(`/assets/${asset.id}`, { method: "PUT", body: form });
      } else {
        await api("/assets", { method: "POST", body: { kind: host ? "host" : "account", name, ...form } });
      }
      setSaved("Fiche enregistrée (classée : les synchronisations ne la modifieront plus).");
      load();
    } catch (err) {
      setSaved(err instanceof Error ? err.message : String(err));
    }
  };

  const open = alerts?.filter((a) => ["new", "in_progress", "waiting"].includes(a.status)) ?? [];
  const Icon = host ? (isServer(name) || asset?.asset_type === "serveur" ? Server : Monitor) : UserIcon;

  return (
    <>
      <PageHeader title={asset?.display_name ?? name} icon={Icon}
        subtitle={[host ? (asset?.asset_type || (isServer(name) ? "serveur" : "machine")) : "compte", asset?.owner, asset?.service].filter(Boolean).join(" · ")}>
        <Link to={`/search?${new URLSearchParams({ q: condition, period: "30d" })}`} className="button ghost">
          <SearchIcon size={14} /> Rechercher dans les journaux
        </Link>
      </PageHeader>
      <p className="breadcrumb">
        <Link to="/assets"><ArrowLeft size={13} /> Inventaire</Link>
      </p>
      <ErrorBanner error={error} />

      <div className="asset-kpis">
        <div className={`kpi-mini crit-${asset?.criticality ?? "normal"}`}>
          <strong>{CRITICALITY.find((c) => c.value === (asset?.criticality ?? "normal"))?.label}</strong>
          <span>criticité{asset ? "" : " (pas de fiche)"}</span>
        </div>
        <div className="kpi-mini"><strong>{formatNumber(open.length)}</strong><span>alerte(s) ouverte(s)</span></div>
        <div className="kpi-mini"><strong>{formatNumber(alerts?.length ?? 0)}</strong><span>alerte(s) au total</span></div>
        <div className="kpi-mini"><strong>{events?.total !== undefined && events?.total !== null ? formatNumber(events.total) : "…"}</strong><span>événements (30 jours)</span></div>
      </div>

      <div className="grid-2 detail">
        <Card title="Inventaire" icon={Icon}>
          {asset === null && <p className="muted small">Cette {host ? "machine" : "identité"} n'a pas encore de fiche : la renseigner la classe dans l'inventaire.</p>}
          <div className="asset-form">
            <label>
              Criticité
              <select value={form.criticality} disabled={!editable} onChange={(e) => setForm({ ...form, criticality: e.target.value as Criticality })}>
                {CRITICALITY.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
              </select>
            </label>
            <label>
              Propriétaire
              <input value={form.owner} disabled={!editable} onChange={(e) => setForm({ ...form, owner: e.target.value })} placeholder="ex. Directeur général des services" />
            </label>
            <label>
              Service
              <input value={form.service} disabled={!editable} onChange={(e) => setForm({ ...form, service: e.target.value })} placeholder="ex. Ressources humaines" />
            </label>
            {host && (
              <label className="checkbox wide">
                <input type="checkbox" checked={form.internet_exposed} disabled={!editable}
                  onChange={(e) => setForm({ ...form, internet_exposed: e.target.checked })} />
                Exposée à Internet (service publié : site web, messagerie, VPN, accès distant…)
              </label>
            )}
            <label className="wide">
              Description
              <textarea rows={2} value={form.description} disabled={!editable} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </label>
          </div>
          {editable && (
            <div className="row">
              <button type="button" className="primary" onClick={save}>{asset ? "Enregistrer" : "Créer la fiche"}</button>
              {saved && <span className="small">{saved}</span>}
            </div>
          )}
          {asset && <p className="muted small">Source : {asset.source}{asset.reviewed ? " · classée par la DSI" : " · à classer"}</p>}
        </Card>

        <Card title="Activité sur 30 jours, par outil" icon={Activity}>
          {timeline === null ? <p className="muted">Chargement…</p> : timeline.rows.length ? <Timeline rows={timeline.rows} series /> : <Empty>Aucun événement sur 30 jours.</Empty>}
        </Card>
      </div>

      <RiskCard kind={host ? "host" : "account"} name={name} />

      <Card title={`Alertes (${alerts?.length ?? 0})`} icon={Siren}>
        {alerts && alerts.length === 0 ? (
          <Empty>Aucune alerte ne cite {host ? "cette machine" : "ce compte"}.</Empty>
        ) : (
          <div className="table-scroll">
            <table className="alerts-table">
              <thead>
                <tr><th>Priorité</th><th>Sévérité</th><th>Outil</th><th>Alerte</th><th className="num">Nombre</th><th>Activité</th><th>Statut</th></tr>
              </thead>
              <tbody>
                {alerts?.map((a) => (
                  <tr key={a.id}>
                    <td><PriorityPill score={a.priority} reasons={a.priority_reasons} /></td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td className="tool-cell">{a.modules.length ? a.modules.map((m) => <ToolBadge key={m} module={m} />) : <ToolBadge />}</td>
                    <td className="alert-cell"><Link to={`/alerts/${a.id}`} title={a.title}><DetectionName name={detectionName(a)} /></Link></td>
                    <td className="num">{formatNumber(a.count)}</td>
                    <td className="nowrap">{timeAgo(a.last_seen)}<div className="muted small">depuis le {formatDate(a.first_seen)}</div></td>
                    <td><StatusBadge status={a.status as AlertStatus} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Derniers événements (30 jours)" icon={Activity}>
        {events === null ? (
          <p className="muted">Chargement…</p>
        ) : events.events.length === 0 ? (
          <Empty>Aucun événement.</Empty>
        ) : (
          <div className="table-scroll">
            <table className="search-table">
              <thead><tr><th>Date</th><th>Outil</th><th>{host ? "Compte" : "Machine"}</th><th>Source → destination</th><th>Détection / message</th><th /></tr></thead>
              <tbody>
                {events.events.map((e) => (
                  <tr key={String(e.event_id)}>
                    <td className="nowrap">{formatDate(String(e.ts))}</td>
                    <td><ToolBadge module={String(e.module)} /></td>
                    <td className="mono small">
                      {host
                        ? e.user_name ? <Link to={`/assets/account/${encodeURIComponent(String(e.user_name))}`}>{String(e.user_name)}</Link> : "—"
                        : e.host_name ? <Link to={`/assets/host/${encodeURIComponent(String(e.host_name))}`}>{String(e.host_name)}</Link> : "—"}
                    </td>
                    <td className="mono small">{[e.source_ip, e.destination_ip].filter(Boolean).join(" → ") || "—"}</td>
                    <td className="small search-msg">{e.rule_name ? <strong>{String(e.rule_name)} </strong> : null}{String(e.message ?? "").slice(0, 200)}</td>
                    <td>{e.reference ? <a className="console-link" href={String(e.reference)} target="_blank" rel="noopener noreferrer" title="Console d'origine"><ExternalLink size={13} /></a> : null}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
