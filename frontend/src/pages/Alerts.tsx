import { ExternalLink, Layers, List, X } from "lucide-react";
import { Siren } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, query } from "../api";
import { canEdit, useUser } from "../App";
import { DetectionName, ToolBadge, detectionName, residualEntity } from "../components/AlertBits";
import DetectionTopics from "../components/DetectionTopics";
import { BulkActions } from "../components/BulkActions";
import { OverdueBadge, ToolStateLine } from "../components/Followup";
import { HostChips } from "../components/Hosts";
import { CategoryBadge, PriorityPill } from "../components/Priority";
import { sourceClosureShort } from "../components/SourceClosure";
import IncidentPicker, { IncidentBadge } from "../components/IncidentPicker";
import { Empty, ErrorBanner, PageHeader, SeverityBadge, StatusBadge, VerdictBadge } from "../components/ui";
import { usePolling } from "../hooks";
import { SEVERITIES, SEVERITY_LABEL, STATUS_LABEL, formatDate, formatNumber, formatShort, moduleLabel, timeAgo } from "../labels";
import type { Alert, AlertStatus } from "../types";

const ACTIVE = "new,in_progress,waiting";
const STATUS_FILTERS: { value: string; label: string; counts: AlertStatus[] }[] = [
  { value: ACTIVE, label: "Actives", counts: ["new", "in_progress", "waiting"] },
  { value: "new", label: STATUS_LABEL.new, counts: ["new"] },
  { value: "in_progress", label: STATUS_LABEL.in_progress, counts: ["in_progress"] },
  { value: "waiting", label: STATUS_LABEL.waiting, counts: ["waiting"] },
  { value: "resolved,false_positive", label: "Clôturées", counts: ["resolved", "false_positive"] },
  { value: "", label: "Toutes", counts: ["new", "in_progress", "waiting", "resolved", "false_positive"] },
];
const PERIODS: { value: string; label: string; hours?: number }[] = [
  { value: "", label: "Toute période" },
  { value: "24h", label: "Dernières 24 h", hours: 24 },
  { value: "7d", label: "7 derniers jours", hours: 24 * 7 },
  { value: "30d", label: "30 derniers jours", hours: 24 * 30 },
  { value: "custom", label: "Dates choisies…" },
];
const SORT_KEY = "minisoc.alerts.sort";
const SORTS: { value: string; label: string }[] = [
  { value: "priority", label: "Priorité" },
  { value: "recent", label: "Activité la plus récente" },
  { value: "severity", label: "Sévérité" },
  { value: "count", label: "Nombre d'occurrences" },
  { value: "oldest", label: "Plus anciennes d'abord" },
];
const VERDICTS: { value: string; label: string }[] = [
  { value: "attack", label: "Attaque" },
  { value: "suspicious", label: "Suspect" },
  { value: "benign", label: "Erreur d'utilisateur" },
];
const PAGE_SIZES = [50, 100, 200, 500];
const FILTER_KEYS = ["severity_min", "module", "host_kind", "category", "detection", "overdue", "rule_id", "verdict", "assignee", "period", "from", "to", "q"];

interface Facets {
  modules: string[];
  rules: { id: string; name: string }[];
  assignees: string[];
}

const today = () => new Date().toLocaleDateString("sv-SE"); // AAAA-MM-JJ, heure locale

/** Période choisie → bornes ISO (relatives : recalculées à chaque rafraîchissement). */
function bounds(period: string, from: string, to: string): { since?: string; until?: string } {
  const preset = PERIODS.find((p) => p.value === period);
  if (preset?.hours) return { since: new Date(Date.now() - preset.hours * 3600000).toISOString() };
  if (period !== "custom") return {};
  return {
    since: from ? new Date(`${from}T00:00:00`).toISOString() : undefined,
    until: to ? new Date(`${to}T23:59:59.999`).toISOString() : undefined,
  };
}

export default function Alerts() {
  const [params, setParams] = useSearchParams();
  const get = (key: string, fallback = "") => params.get(key) ?? fallback;
  const status = get("status", ACTIVE);
  const period = get("period");
  const from = get("from");
  const to = get("to");
  // Tri : celui de l'adresse, sinon le dernier choisi (mémorisé sur ce poste), sinon la priorité
  const sort = get("sort", localStorage.getItem(SORT_KEY) || "priority");
  const setSort = (value: string) => {
    localStorage.setItem(SORT_KEY, value);
    update({ sort: value });
  };
  const view = get("view");
  const pageSize = Number(get("size", "50")) || 50;
  const q = get("q");
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState(q);
  const user = useUser();
  const editable = canEdit(user);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const { data: facets } = usePolling(() => api<Facets>("/alerts/facets"), [], 300000);

  const filters = {
    severity_min: get("severity_min"),
    module: get("module"),
    host_kind: get("host_kind"),
    category: get("category"),
    detection: get("detection"),
    overdue: get("overdue"),
    rule_id: get("rule_id"),
    verdict: get("verdict"),
    assignee: get("assignee"),
    q,
  };
  const { data, error, reload } = usePolling(
    () =>
      api<{ total: number; by_status: Partial<Record<AlertStatus, number>>; items: Alert[] }>(
        `/alerts${query({ status, ...filters, ...bounds(period, from, to), sort, limit: pageSize, offset: page * pageSize })}`,
      ),
    [status, period, from, to, sort, pageSize, page, ...Object.values(filters)],
    15000,
  );

  const update = (changes: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value);
      else next.delete(key);
      if (key === "status" && !value) next.set("status", "");
    }
    setParams(next);
    setPage(0);
  };
  const filtered = FILTER_KEYS.some((k) => params.get(k));
  const reset = () => {
    const next = new URLSearchParams(params);
    FILTER_KEYS.forEach((k) => next.delete(k));
    setParams(next);
    setSearch("");
    setPage(0);
  };
  const countOf = (statuses: AlertStatus[]) =>
    data ? statuses.reduce((sum, s) => sum + (data.by_status[s] ?? 0), 0) : null;
  const pages = data ? Math.ceil(data.total / pageSize) : 0;

  return (
    <>
      <PageHeader title="Alertes" icon={Siren} subtitle="Détections à qualifier et à traiter">
        <div className="segmented" role="tablist" aria-label="Vue">
          <button role="tab" aria-selected={view !== "detections"} className={view !== "detections" ? "active" : ""} onClick={() => update({ view: "" })}>
            <List size={14} /> Alertes{data ? ` (${formatNumber(data.total)})` : ""}
          </button>
          <button role="tab" aria-selected={view === "detections"} className={view === "detections" ? "active" : ""} onClick={() => update({ view: "detections" })}>
            <Layers size={14} /> Par détection
          </button>
        </div>
      </PageHeader>
      {view === "detections" ? (
        <DetectionTopics editable={editable} />
      ) : (
      <>

      <div className="filters">
        <div className="segmented" role="group" aria-label="Statut">
          {STATUS_FILTERS.map((f) => {
            const n = countOf(f.counts);
            return (
              <button key={f.label} className={status === f.value ? "active" : ""} onClick={() => update({ status: f.value })}>
                {f.label}
                {n !== null && <span className="count">{formatNumber(n)}</span>}
              </button>
            );
          })}
        </div>
        <label className="inline">
          Période
          <select
            value={period}
            onChange={(e) =>
              update(e.target.value === "custom" ? { period: "custom", from: from || today(), to: to || today() } : { period: e.target.value, from: "", to: "" })
            }
          >
            {PERIODS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
        {period === "custom" && (
          <>
            <label className="inline">
              Du
              <input type="date" value={from} max={to || today()} onChange={(e) => update({ from: e.target.value })} />
            </label>
            <label className="inline">
              au
              <input type="date" value={to} min={from} max={today()} onChange={(e) => update({ to: e.target.value })} />
            </label>
          </>
        )}
      </div>

      <div className="followup-views" role="group" aria-label="Suivi">
        <span className="muted small">Suivi :</span>
        {([
          { label: "Mes alertes", active: filters.assignee === "me", apply: { assignee: filters.assignee === "me" ? "" : "me" } },
          { label: "Non assignées", active: filters.assignee === "none", apply: { assignee: filters.assignee === "none" ? "" : "none" } },
          { label: "En attente", active: status === "waiting", apply: { status: status === "waiting" ? ACTIVE : "waiting" } },
          { label: "En retard", active: filters.overdue === "true", apply: { overdue: filters.overdue === "true" ? "" : "true" } },
        ] as { label: string; active: boolean; apply: Record<string, string> }[]).map((v) => (
          <button key={v.label} type="button" className={`view-chip ${v.active ? "active" : ""}`} onClick={() => update(v.apply)}>
            {v.label}
          </button>
        ))}
      </div>

      <div className="filters">
        <select value={filters.severity_min} onChange={(e) => update({ severity_min: e.target.value })} aria-label="Sévérité minimale">
          <option value="">Toutes sévérités</option>
          {SEVERITIES.filter((s) => s !== "info").map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABEL[s]}
              {s === "critical" ? "" : " et plus"}
            </option>
          ))}
        </select>
        <select value={filters.module} onChange={(e) => update({ module: e.target.value })} aria-label="Source">
          <option value="">Toutes sources</option>
          {facets?.modules.map((m) => (
            <option key={m} value={m}>
              {moduleLabel(m)}
            </option>
          ))}
        </select>
        <select value={filters.host_kind} onChange={(e) => update({ host_kind: e.target.value })} aria-label="Type de machine">
          <option value="">Toutes machines</option>
          <option value="server">Serveurs</option>
          <option value="workstation">Postes de travail</option>
        </select>
        <select value={filters.category} onChange={(e) => update({ category: e.target.value })} aria-label="Catégorie">
          <option value="">Toutes catégories</option>
          <option value="threat">Menaces</option>
          <option value="hygiene">Hygiène du parc</option>
          <option value="info">Information</option>
        </select>
        <select value={filters.rule_id} onChange={(e) => update({ rule_id: e.target.value })} aria-label="Règle">
          <option value="">Toutes règles</option>
          {facets?.rules.map((r) => (
            <option key={r.id} value={r.id}>
              {r.id} – {r.name}
            </option>
          ))}
        </select>
        <select value={filters.verdict} onChange={(e) => update({ verdict: e.target.value })} aria-label="Qualification">
          <option value="">Toutes qualifications</option>
          {VERDICTS.map((v) => (
            <option key={v.value} value={v.value}>
              {v.label}
            </option>
          ))}
        </select>
        <select value={filters.assignee} onChange={(e) => update({ assignee: e.target.value })} aria-label="Assignation">
          <option value="">Toutes assignations</option>
          <option value="me">Assignées à moi</option>
          <option value="none">Non assignées</option>
          {facets?.assignees.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            update({ q: search.trim() });
          }}
        >
          <input type="search" placeholder="Rechercher (titre, IP, compte, poste…)" value={search} onChange={(e) => setSearch(e.target.value)} />
        </form>
        {filtered && (
          <button type="button" className="link" onClick={reset}>
            Réinitialiser les filtres
          </button>
        )}
        <span className="spacer" />
        <div className="sort-toggle" role="group" aria-label="Ordre de la liste">
          <button type="button" className={sort === "priority" ? "active" : ""} onClick={() => setSort("priority")}>
            Par priorité
          </button>
          <button type="button" className={sort === "recent" ? "active" : ""} onClick={() => setSort("recent")}>
            Plus récentes
          </button>
        </div>
        <select value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Tri">
          {SORTS.map((s) => (
            <option key={s.value} value={s.value}>
              Tri : {s.label}
            </option>
          ))}
        </select>
      </div>

      {filters.detection && (
        <div className="active-filter">
          Détection : <strong>{filters.detection}</strong>
          <button type="button" className="icon-button" aria-label="Retirer ce filtre" onClick={() => update({ detection: "" })}>
            <X size={14} />
          </button>
        </div>
      )}
      <ErrorBanner error={error} />
      {editable && selected.size > 0 && (
        <div className="selection-bar">
          <strong>{selected.size} alerte(s) sélectionnée(s)</strong>
          <BulkActions ids={[...selected]} onDone={() => { setSelected(new Set()); reload(); }} />
          <IncidentPicker
            key={[...selected].join(",")}
            alertIds={[...selected]}
            compact
            onDone={() => {
              setSelected(new Set());
              reload();
            }}
          />
          <button type="button" className="link" onClick={() => setSelected(new Set())}>
            Désélectionner
          </button>
        </div>
      )}
      {data && data.items.length === 0 ? (
        <Empty>Aucune alerte ne correspond aux filtres.</Empty>
      ) : (
        <div className="table-scroll">
        <table className="alerts-table">
          <thead>
            <tr>
              {editable && (
                <th>
                  <input
                    type="checkbox"
                    aria-label="Tout sélectionner sur la page"
                    checked={!!data?.items.length && data.items.every((a) => selected.has(a.id))}
                    onChange={(e) => {
                      const next = new Set(selected);
                      data?.items.forEach((a) => (e.target.checked ? next.add(a.id) : next.delete(a.id)));
                      setSelected(next);
                    }}
                  />
                </th>
              )}
              <th title="Priorité de traitement (0-100) : survolez le score pour le détail">Priorité</th>
              <th>Sévérité</th>
              <th>Outil</th>
              <th>Alerte</th>
              <th>Machines</th>
              <th className="num">Nombre</th>
              <th>Activité</th>
              <th>Statut</th>
              <th aria-label="Console d'origine" />
            </tr>
          </thead>
          <tbody>
            {data?.items.map((a) => (
              <tr key={a.id} className={selected.has(a.id) ? "selected" : ""}>
                {editable && (
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`Sélectionner l'alerte ${a.id}`}
                      checked={selected.has(a.id)}
                      onChange={(e) => {
                        const next = new Set(selected);
                        if (e.target.checked) next.add(a.id);
                        else next.delete(a.id);
                        setSelected(next);
                      }}
                    />
                  </td>
                )}
                <td>
                  <PriorityPill score={a.priority} reasons={a.priority_reasons} />
                </td>
                <td>
                  <SeverityBadge severity={a.severity} />
                </td>
                <td className="tool-cell">
                  {a.modules.length ? a.modules.map((m) => <ToolBadge key={m} module={m} />) : <ToolBadge />}
                </td>
                <td className="alert-cell">
                  <Link to={`/alerts/${a.id}`} title={a.title}>
                    <DetectionName name={detectionName(a)} />
                  </Link>{" "}
                  <VerdictBadge verdict={a.verdict} label={a.verdict_label} />
                  <CategoryBadge category={a.category} />
                  {a.incident_id && <IncidentBadge id={a.incident_id} />}
                  <div className="muted small alert-meta" title={`${a.rule_id} · ${a.entity_key}`}>
                    <span className="rule-chip">{a.rule_id}</span> {residualEntity(a.entity_key)}
                  </div>
                </td>
                <td className="hosts-cell">
                  <HostChips hosts={a.hosts ?? []} />
                </td>
                <td className="num">{formatNumber(a.count)}</td>
                <td className="nowrap" title={`Dernière : ${formatDate(a.last_seen)}`}>
                  {timeAgo(a.last_seen)}
                  <div className="muted small">depuis le {formatShort(a.first_seen)}</div>
                </td>
                <td className="nowrap">
                  <StatusBadge status={a.status as AlertStatus} /> <OverdueBadge alert={a} />
                  {a.source_closure ? (
                    <div className="small closed-in" title={`Clôturée dans ${a.source_closure.tool} : ${a.source_closure.label}`}>
                      {sourceClosureShort(a.source_closure)}
                    </div>
                  ) : (
                    <div className="muted small">{a.assignee ?? "non assignée"}</div>
                  )}
                  <ToolStateLine alert={a} />
                </td>
                <td>
                  {a.reference && (
                    <a
                      href={a.reference}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="console-link"
                      title={`Ouvrir dans la console ${moduleLabel(a.modules[0] ?? "")}`}
                    >
                      <ExternalLink size={14} />
                    </a>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}
      {data && data.total > 0 && (
        <div className="pager">
          <button disabled={page === 0} onClick={() => setPage(page - 1)}>
            Précédentes
          </button>
          <span>
            Page {page + 1} / {Math.max(1, pages)}
          </span>
          <button disabled={(page + 1) * pageSize >= data.total} onClick={() => setPage(page + 1)}>
            Suivantes
          </button>
          <label className="inline">
            Par page
            <select value={pageSize} onChange={(e) => update({ size: e.target.value === "50" ? "" : e.target.value })}>
              {PAGE_SIZES.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
        </div>
      )}
      </>
      )}
    </>
  );
}
