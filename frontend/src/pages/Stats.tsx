import { Activity, CalendarClock, ChartNoAxesCombined, Info, Gauge, HardDrive, Target, Timer, TriangleAlert, Waypoints } from "lucide-react";
import { Fragment, useMemo, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, query } from "../api";
import { Card, Empty, ErrorBanner, PageHeader } from "../components/ui";
import { usePolling } from "../hooks";
import { SEVERITY_LABEL, STATUS_LABEL, formatNumber, formatShort, moduleLabel } from "../labels";
import type { AlertStatus, Severity } from "../types";

interface Dist {
  count: number;
  median: number | null;
  p90: number | null;
}
type BySeverity<T> = Record<Severity, T>;
interface QualityRow {
  total: number;
  open: number;
  resolved: number;
  false_positive: number;
  closed: number;
  fp_rate: number | null;
  closed_by: { human: number; system: number; source: number };
  noisy: boolean;
}
interface Ranked {
  alerts: number;
  severity: Severity;
  tools: string[];
  rules: number;
}
interface Source {
  module: string;
  total: number;
  previous: number;
  delta_pct: number | null;
  series: number[];
  monitored: boolean;
  first: string | null;
  last: string | null;
  max_silence_minutes?: number;
  silences?: number;
  silent_minutes?: number;
  availability?: number;
  longest?: { start: string; end: string; minutes: number }[];
}
type Grid = number[][];
interface HeatSummary {
  total: number;
  off_hours: number;
  off_hours_pct: number | null;
  peak: { day: string; hour: number; count: number } | null;
}
interface Filesystem {
  mount: string;
  device: string;
  fstype: string;
  size: number;
  used: number;
  avail: number;
  percent: number;
  inodes_percent: number;
  over: boolean;
}
interface Disks {
  state: "ok" | "alert" | "stale" | "absent" | "error";
  error: string;
  at: string | null;
  age_minutes: number | null;
  host: string;
  threshold: number;
  high: number;
  filesystems: Filesystem[];
}
interface Analytics {
  period: { since: string; until: string; previous_since: string; timezone: string };
  events_error: string;
  disks: Disks | null;
  sources: {
    granularity: "day" | "week";
    buckets: string[];
    total: number;
    previous_total: number;
    sources: Source[];
    silence_alerts: number;
    data_start: string;
    method: string[];
  };
  heatmap: {
    grids: { alerts: Grid; failures: Grid; successes: Grid };
    summary: { alerts: HeatSummary; failures: HeatSummary; successes: HeatSummary };
    business: { days: number[]; start: number; end: number };
    offhours_accounts: { user: string; n: number; ips: number; hosts: number; modules: string[]; last: string }[];
    method: string[];
  };
  correlation: {
    multi_tool_alerts: number;
    considered: number;
    corroborated_hosts: { host: string; tools: string[]; alerts: number }[];
    corroborated_total: number;
    derived: (QualityRow & { rule_id: string; label: string })[];
    recent: { id: number; rule_id: string; title: string; severity: Severity; status: AlertStatus; created_at: string; why: string }[];
    incidents: { opened: number; automatic: number };
    blocks: { total: number; ips: number; active: number; failed: number; removed_manual: number; expired: number; from_alert: number };
    isolations: { requested: number; failed: number; released: number; hosts: string[] };
    method: string[];
  };
  volumes: {
    granularity: "day" | "week";
    total: number;
    occurrences: number;
    previous_total: number;
    delta_pct: number | null;
    by_severity: BySeverity<number>;
    by_category: { category: string; label: string; count: number }[];
    timeline: ({ bucket: string } & BySeverity<number>)[];
    tool_series: { buckets: string[]; series: Record<string, number[]> };
    by_tool: ({ module: string; total: number } & BySeverity<number>)[];
    by_rule: { rule_id: string; rule_name: string; total: number; occurrences: number; severity: Severity; tools: string[] }[];
    method: string[];
  };
  quality: QualityRow & {
    untraced: number;
    verdicts: Partial<Record<"attack" | "suspicious" | "benign", number>>;
    by_rule: (QualityRow & { rule_id: string; rule_name: string })[];
    by_tool: (QualityRow & { module: string })[];
    noisy_rules: (QualityRow & { rule_id: string; rule_name: string })[];
    method: string[];
  };
  delays: {
    granularity: "day" | "week";
    acknowledge: { all: Dist } & BySeverity<Dist>;
    close_human: { all: Dist } & BySeverity<Dist>;
    close_system: Dist;
    close_source: Dist;
    never_acknowledged_open: number;
    timeline: { bucket: string; acknowledge: number | null; close: number | null }[];
    backlog: ({ age: string; label: string; total: number } & BySeverity<number>)[];
    backlog_total: number;
    incidents: {
      opened: number;
      closed: number;
      still_open: number;
      time_to_contain: Dist;
      time_to_close: Dist;
      by_category: { category: string; count: number }[];
    };
    method: string[];
  };
  mitre: {
    considered: number;
    excluded: number;
    unmapped: number;
    tactics: { id: string; name: string; alerts: number; exclusive: number; rules: number; entities: number }[];
    techniques: { id: string; name: string; alerts: number; rules: string[]; tactics: string[] }[];
    hosts: (Ranked & { kind: "host"; name: string; tactics: number; last: string })[];
    accounts: (Ranked & { kind: "user"; name: string; tactics: number; last: string })[];
    ips: (Ranked & { ip: string })[];
    method: string[];
  };
}

const PERIODS = [
  { value: "7d", label: "7 jours", days: 7 },
  { value: "30d", label: "30 jours", days: 30 },
  { value: "90d", label: "90 jours", days: 90 },
  { value: "365d", label: "12 mois", days: 365 },
  { value: "custom", label: "Dates…", days: 0 },
];
const VERDICT_LABEL = { attack: "attaque", suspicious: "suspect", benign: "erreur d'utilisateur" };
const INCIDENT_CATEGORY: Record<string, string> = {
  compromission_compte: "Compromission de compte", malware: "Logiciel malveillant", rancongiciel: "Rançongiciel",
  hameconnage: "Hameçonnage", intrusion: "Intrusion", fuite_donnees: "Fuite de données", deni_service: "Déni de service",
  autre: "Autre",
};
const BY_SEVERITY: Severity[] = ["critical", "high", "medium", "low", "info"];
const TOOL_CLASSES = ["tool-0", "tool-1", "tool-2", "tool-3", "tool-4", "tool-5", "tool-6"];

const localDay = (d: Date) => d.toLocaleDateString("sv-SE");
const signed = (n: number) => `${n > 0 ? "+" : ""}${n}`;

function duration(minutes: number | null): string {
  if (minutes === null) return "—";
  if (minutes < 60) return `${Math.round(minutes)} min`;
  if (minutes < 48 * 60) return `${(minutes / 60).toFixed(1).replace(".", ",")} h`;
  return `${(minutes / 1440).toFixed(1).replace(".", ",")} j`;
}

/** Période choisie → bornes envoyées à l'API ; les dates personnalisées vont de minuit à minuit (heure locale). */
function bounds(period: string, from: string, to: string): { since: Date; until: Date } {
  const now = new Date();
  if (period === "custom" && from && to) {
    const until = new Date(`${to}T00:00:00`);
    until.setDate(until.getDate() + 1);
    return { since: new Date(`${from}T00:00:00`), until };
  }
  const days = PERIODS.find((p) => p.value === period)?.days || 30;
  return { since: new Date(now.getTime() - days * 86400000), until: now };
}

/** Texte de méthode : seul le gras (**…**) est mis en forme. */
function rich(text: string): ReactNode {
  return text.split(/\*\*(.+?)\*\*/g).map((part, i) => (i % 2 ? <strong key={i}>{part}</strong> : part));
}

function Method({ lines }: { lines: string[] }) {
  return (
    <details className="stats-method">
      <summary>
        <Info size={14} /> Méthode de calcul
      </summary>
      <ul>
        {lines.map((line, i) => (
          <li key={i}>{rich(line)}</li>
        ))}
      </ul>
    </details>
  );
}

function niceMax(value: number): number {
  if (value <= 5) return 5;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  return Math.ceil(value / magnitude) * magnitude;
}

function tick(bucket: string): string {
  return `${bucket.slice(8, 10)}/${bucket.slice(5, 7)}`;
}

const W = 760;
const H = 210;
const PAD = { top: 14, right: 12, bottom: 26, left: 44 };

/** Barres empilées par intervalle (jour ou semaine). */
function StackedBars({ buckets, series, granularity, format = formatNumber }: {
  buckets: string[];
  series: { key: string; label: string; className: string; values: number[] }[];
  granularity: "day" | "week";
  format?: (n: number) => string;
}) {
  const totals = buckets.map((_, i) => series.reduce((s, x) => s + x.values[i], 0));
  const max = niceMax(Math.max(0, ...totals));
  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top - PAD.bottom;
  const band = plotW / Math.max(1, buckets.length);
  const y = (v: number) => PAD.top + plotH - (v / max) * plotH;
  const every = Math.max(1, Math.ceil(buckets.length / 12));
  const prefix = granularity === "week" ? "Semaine du " : "";
  return (
    <figure className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Alertes créées par intervalle">
        {[max / 2, max].map((v) => (
          <g key={v}>
            <line x1={PAD.left} x2={W - PAD.right} y1={y(v)} y2={y(v)} className="grid" />
            <text x={PAD.left - 8} y={y(v) + 4} textAnchor="end" className="tick">{format(v)}</text>
          </g>
        ))}
        <line x1={PAD.left} x2={W - PAD.right} y1={y(0)} y2={y(0)} className="baseline" />
        {buckets.map((b, i) => {
          let acc = 0;
          const x = PAD.left + i * band + band * 0.15;
          const w = Math.max(1, band * 0.7);
          return (
            <g key={b}>
              {series.map((s) => {
                const v = s.values[i];
                if (!v) return null;
                const top = y(acc + v);
                const h = y(acc) - top;
                acc += v;
                return (
                  <rect key={s.key} x={x} width={w} y={top} height={h} className={s.className}>
                    <title>{`${prefix}${tick(b)} · ${s.label} : ${format(v)} (total ${format(totals[i])})`}</title>
                  </rect>
                );
              })}
              {i % every === 0 && (
                <text x={x + w / 2} y={H - 6} textAnchor="middle" className="tick">{tick(b)}</text>
              )}
            </g>
          );
        })}
      </svg>
      <figcaption className="legend">
        {series.map((s) => (
          <span key={s.key}>
            <i className={`swatch ${s.className}`} />
            {s.label}
          </span>
        ))}
      </figcaption>
    </figure>
  );
}

/** Médianes par intervalle (prise en charge, clôture) ; un intervalle sans valeur interrompt la courbe. */
function MedianLines({ points, granularity }: { points: Analytics["delays"]["timeline"]; granularity: "day" | "week" }) {
  const lines = [
    { key: "acknowledge" as const, label: "Prise en charge (médiane)", className: "stats-line-ack" },
    { key: "close" as const, label: "Clôture par une personne (médiane)", className: "stats-line-close" },
  ];
  const values = points.flatMap((p) => [p.acknowledge, p.close]).filter((v): v is number => v !== null);
  if (!values.length) return <Empty>Aucune alerte prise en charge ou clôturée sur la période.</Empty>;
  const max = niceMax(Math.max(...values));
  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top - PAD.bottom;
  const step = plotW / Math.max(1, points.length - 1);
  const x = (i: number) => PAD.left + (points.length === 1 ? plotW / 2 : i * step);
  const y = (v: number) => PAD.top + plotH - (v / max) * plotH;
  const every = Math.max(1, Math.ceil(points.length / 12));
  const prefix = granularity === "week" ? "Semaine du " : "";
  return (
    <figure className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Délais médians par intervalle">
        {[max / 2, max].map((v) => (
          <g key={v}>
            <line x1={PAD.left} x2={W - PAD.right} y1={y(v)} y2={y(v)} className="grid" />
            <text x={PAD.left - 8} y={y(v) + 4} textAnchor="end" className="tick">{duration(v)}</text>
          </g>
        ))}
        <line x1={PAD.left} x2={W - PAD.right} y1={y(0)} y2={y(0)} className="baseline" />
        {lines.map((l) => {
          let d = "";
          let pen = false;
          points.forEach((p, i) => {
            const v = p[l.key];
            if (v === null) {
              pen = false;
              return;
            }
            d += `${pen ? "L" : "M"}${x(i)},${y(v)} `;
            pen = true;
          });
          return (
            <g key={l.key} className={l.className}>
              <path d={d} className="stats-line" />
              {points.map((p, i) =>
                p[l.key] === null ? null : (
                  <circle key={i} cx={x(i)} cy={y(p[l.key] as number)} r={3} className="stats-point">
                    <title>{`${prefix}${tick(p.bucket)} · ${l.label} : ${duration(p[l.key])}`}</title>
                  </circle>
                ),
              )}
            </g>
          );
        })}
        {points.map((p, i) =>
          i % every === 0 ? (
            <text key={p.bucket} x={x(i)} y={H - 6} textAnchor="middle" className="tick">{tick(p.bucket)}</text>
          ) : null,
        )}
      </svg>
      <figcaption className="legend">
        {lines.map((l) => (
          <span key={l.key}>
            <i className={`swatch ${l.className}`} />
            {l.label}
          </span>
        ))}
      </figcaption>
    </figure>
  );
}

function Bar({ value, max, className = "stats-possible" }: { value: number; max: number; className?: string }) {
  return (
    <span className="report-track stats-track">
      <span className={`report-fill ${className}`} style={{ width: `${max ? (value / max) * 100 : 0}%` }} />
    </span>
  );
}

function Rate({ value, closed }: { value: number | null; closed: number }) {
  if (value === null) return <span className="muted">—</span>;
  return (
    <span className={value >= 50 && closed >= 5 ? "text-bad" : undefined} title={`sur ${closed} alerte(s) clôturée(s)`}>
      {value} %<span className="muted small"> /{closed}</span>
    </span>
  );
}

function DistCell({ d }: { d: Dist }) {
  if (!d.count) return <td className="num muted" colSpan={3}>—</td>;
  return (
    <>
      <td className="num">{duration(d.median)}</td>
      <td className="num">{duration(d.p90)}</td>
      <td className="num muted">{formatNumber(d.count)}</td>
    </>
  );
}

/** Petite courbe d'événements par intervalle (une barre par jour ou par semaine). */
function Sparkline({ values, buckets }: { values: number[]; buckets: string[] }) {
  const max = Math.max(1, ...values);
  const w = 120;
  const h = 26;
  const band = w / Math.max(1, values.length);
  return (
    <svg className="stats-spark" viewBox={`0 0 ${w} ${h}`} width={w} height={h} role="img" aria-label="Événements par intervalle">
      {values.map((v, i) => (
        <rect key={i} x={i * band + band * 0.1} width={Math.max(0.5, band * 0.8)} y={h - (v / max) * h}
          height={(v / max) * h || 0.5} className={v ? "fill-accent" : "stats-spark-empty"}>
          <title>{`${tick(buckets[i] ?? "")} : ${formatNumber(v)} événements`}</title>
        </rect>
      ))}
    </svg>
  );
}

function gib(bytes: number): string {
  const g = bytes / 1024 ** 3;
  return `${g >= 100 ? Math.round(g) : g.toFixed(1).replace(".", ",")} Gio`;
}

function DisksCard({ d }: { d: Disks | null }) {
  if (!d || d.state === "absent") {
    return (
      <Card title="Disques de la VM" icon={HardDrive}>
        <p className="muted">Aucun relevé : service minisoc-disk absent (installation hors VM, ou VM pas encore mise à jour).</p>
      </Card>
    );
  }
  const over = d.filesystems.filter((f) => f.over);
  return (
    <Card title="Disques de la VM" icon={HardDrive}>
      {d.state === "error" ? (
        <p className="text-bad">Relevé illisible : {d.error}</p>
      ) : (
        <p>
          {d.state === "stale" ? (
            <strong className="text-bad">Relevé arrêté depuis {duration(d.age_minutes)} (alerte UC-63) : sudo journalctl -u minisoc-disk</strong>
          ) : over.length ? (
            <strong className="text-bad">{over.length} partition(s) au-delà de {d.threshold} % : alerte UC-63 ouverte</strong>
          ) : (
            <>Toutes les partitions sous le seuil de {d.threshold} %</>
          )}
          {" "}· relevé {d.at ? formatShort(d.at) : "—"}{d.host ? ` sur ${d.host}` : ""}.
        </p>
      )}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Partition</th>
              <th className="stats-bar-col">Occupation</th>
              <th className="num">Utilisé</th>
              <th className="num">Libre</th>
              <th className="num">Taille</th>
              <th className="num" title="Fichiers : un disque peut être plein sans manquer de place">Inodes</th>
            </tr>
          </thead>
          <tbody>
            {d.filesystems.map((f) => {
              const level = Math.max(f.percent, f.inodes_percent);
              const tone = level >= d.high ? "stats-disk-full" : f.over ? "stats-disk-over" : "stats-certain";
              return (
                <tr key={f.mount}>
                  <td><code>{f.mount}</code> <span className="muted small">{f.device} · {f.fstype}</span></td>
                  <td>
                    <span className="report-track stats-disk-track" title={`${f.percent} %`}>
                      <span className={`report-fill ${tone}`} style={{ width: `${f.percent}%` }} />
                    </span>
                  </td>
                  <td className={`num ${f.percent >= d.threshold ? "text-bad" : ""}`}>{gib(f.used)} · {f.percent} %</td>
                  <td className="num">{gib(f.avail)}</td>
                  <td className="num muted">{gib(f.size)}</td>
                  <td className={`num ${f.inodes_percent >= d.threshold ? "text-bad" : "muted"}`}>{f.inodes_percent} %</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <Method lines={[
        "Relevé toutes les 5 minutes par le service minisoc-disk de la VM (le Mini-SOC tourne dans des conteneurs qui ne voient pas les disques de l'hôte) ; une ligne par système de fichiers local, montages liés comptés une fois.",
        `Occupation comme df : espace utilisé ÷ espace accessible (réserve de root exclue). Alerte UC-63 au-delà de ${d.threshold} % en espace ou en inodes (Paramètres › Détection), haute à partir de ${d.high} % ; clôturée automatiquement sous ${d.threshold - 3} %.`,
        "Un relevé vieux de plus d'une heure déclenche aussi l'alerte : sans lui, la VM pourrait se remplir sans que personne ne le voie.",
      ]} />
    </Card>
  );
}

function SourcesCard({ s, error }: { s: Analytics["sources"]; error: string }) {
  const silent = s.sources.filter((x) => x.monitored && (x.silences ?? 0) > 0);
  return (
    <Card title="Santé des sources" icon={Activity}>
      {error ? (
        <p className="text-bad">{error} : volumes et silences non calculés.</p>
      ) : (
        <p>
          <strong>{formatNumber(s.total)}</strong> événements reçus ({s.previous_total ? `${signed(Math.round((100 * (s.total - s.previous_total)) / s.previous_total))} % vs période précédente` : "période précédente vide"}) ·{" "}
          {silent.length ? <strong className="text-bad">{silent.length} source(s) surveillée(s) avec au moins un silence</strong> : "aucun silence sur les sources surveillées"} ·{" "}
          {s.silence_alerts} alerte(s) « source silencieuse ».
        </p>
      )}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Source</th>
              <th className="num">Événements</th>
              <th className="num">vs préc.</th>
              <th>{s.granularity === "day" ? "Par jour" : "Par semaine"}</th>
              <th className="num" title="Délai de silence toléré">Délai</th>
              <th className="num">Disponibilité</th>
              <th className="num">Silences</th>
              <th>Plus long silence</th>
            </tr>
          </thead>
          <tbody>
            {s.sources.map((x) => (
              <tr key={x.module}>
                <td>{moduleLabel(x.module)}</td>
                <td className="num">{formatNumber(x.total)}</td>
                <td className={`num ${x.delta_pct !== null && x.delta_pct <= -50 ? "text-bad" : "muted"}`}>
                  {x.delta_pct === null ? "—" : `${signed(x.delta_pct)} %`}
                </td>
                <td><Sparkline values={x.series} buckets={s.buckets} /></td>
                {x.monitored ? (
                  <>
                    <td className="num muted">{duration(x.max_silence_minutes ?? null)}</td>
                    <td className={`num ${(x.availability ?? 100) < 99 ? "text-bad" : ""}`}>
                      {(x.availability ?? 0).toFixed(1).replace(".", ",")} %
                    </td>
                    <td className="num" title={`${duration(x.silent_minutes ?? 0)} cumulés`}>
                      {x.silences ? `${x.silences} · ${duration(x.silent_minutes ?? 0)}` : <span className="muted">0</span>}
                    </td>
                    <td className="small">
                      {x.longest?.[0] ? `${formatShort(x.longest[0].start)} → ${formatShort(x.longest[0].end)} (${duration(x.longest[0].minutes)})` : <span className="muted">—</span>}
                    </td>
                  </>
                ) : (
                  <td colSpan={4} className="muted small">non surveillée (pas de délai de silence)</td>
                )}
              </tr>
            ))}
            {!s.sources.length && <tr><td colSpan={8} className="muted">Aucun événement sur la période.</td></tr>}
          </tbody>
        </table>
      </div>
      <Method lines={s.method} />
    </Card>
  );
}

const HEAT_METRICS = [
  { key: "alerts" as const, label: "Alertes" },
  { key: "failures" as const, label: "Échecs d'authentification" },
  { key: "successes" as const, label: "Connexions réussies" },
];
const DAYS = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];

function HeatmapCard({ h, error }: { h: Analytics["heatmap"]; error: string }) {
  const [metric, setMetric] = useState<"alerts" | "failures" | "successes">("alerts");
  const grid = h.grids[metric];
  const summary = h.summary[metric];
  const max = Math.max(1, ...grid.flat());
  const business = (d: number, hr: number) => h.business.days.includes(d + 1) && hr >= h.business.start && hr < h.business.end;
  return (
    <Card title="Activité par jour et heure" icon={CalendarClock}>
      <div className="stats-toolbar">
        <span className="muted">
          {formatNumber(summary.total)} au total ·{" "}
          <strong className={summary.off_hours_pct !== null && summary.off_hours_pct >= 30 ? "text-bad" : undefined}>
            {summary.off_hours_pct === null ? "—" : `${summary.off_hours_pct} %`} hors heures ouvrées
          </strong>{" "}
          ({formatNumber(summary.off_hours)})
          {summary.peak && <> · pic le {summary.peak.day} à {summary.peak.hour} h ({formatNumber(summary.peak.count)})</>}
        </span>
        <div className="segmented" role="group" aria-label="Indicateur">
          {HEAT_METRICS.map((m) => (
            <button key={m.key} type="button" className={metric === m.key ? "active" : ""} onClick={() => setMetric(m.key)}>
              {m.label}
            </button>
          ))}
        </div>
      </div>
      {error && metric !== "alerts" ? (
        <p className="text-bad">{error} : répartition de l'authentification non calculée.</p>
      ) : (
        <div className="stats-heat" role="table" aria-label="Répartition par jour et par heure">
          <span />
          {Array.from({ length: 24 }, (_, hr) => (
            <span key={hr} className="stats-heat-hour">{hr % 3 === 0 ? `${hr}h` : ""}</span>
          ))}
          {grid.map((row, d) => (
            <Fragment key={d}>
              <span className="stats-heat-day">{DAYS[d].slice(0, 3)}.</span>
              {row.map((v, hr) => (
                <span key={hr} className={`stats-heat-cell ${business(d, hr) ? "business" : ""}`}
                  style={{ ["--level" as string]: v ? 0.15 + 0.85 * (v / max) : 0 }}
                  title={`${DAYS[d]} ${hr} h - ${hr + 1} h : ${formatNumber(v)}${business(d, hr) ? " (heures ouvrées)" : " (hors heures ouvrées)"}`} />
              ))}
            </Fragment>
          ))}
        </div>
      )}
      <p className="muted small">Cases encadrées : heures ouvrées. Plus la case est colorée, plus le volume est élevé (échelle propre à l'indicateur affiché).</p>
      <h3>Comptes connectés hors heures ouvrées</h3>
      <table>
        <thead>
          <tr>
            <th>Compte</th>
            <th className="num">Connexions</th>
            <th className="num">Adresses IP</th>
            <th className="num">Machines</th>
            <th>Sources</th>
            <th>Dernière</th>
          </tr>
        </thead>
        <tbody>
          {h.offhours_accounts.map((a) => (
            <tr key={a.user}>
              <td><Link to={`/assets/account/${encodeURIComponent(a.user)}`} className="mono">{a.user}</Link></td>
              <td className="num">{formatNumber(a.n)}</td>
              <td className="num">{formatNumber(a.ips)}</td>
              <td className="num">{formatNumber(a.hosts)}</td>
              <td className="small muted">{a.modules.map(moduleLabel).join(", ")}</td>
              <td className="small">{formatShort(a.last)}</td>
            </tr>
          ))}
          {!h.offhours_accounts.length && <tr><td colSpan={6} className="muted">{error ? "Non calculé." : "Aucune connexion hors heures ouvrées."}</td></tr>}
        </tbody>
      </table>
      <Method lines={h.method} />
    </Card>
  );
}

function CorrelationCard({ c, alertsLink }: { c: Analytics["correlation"]; alertsLink: (extra?: Record<string, string>) => string }) {
  const b = c.blocks;
  const iso = c.isolations;
  return (
    <Card title="Corrélation et réponse" icon={Waypoints}>
      <p>
        <strong>{formatNumber(c.multi_tool_alerts)}</strong> alerte(s) portant plusieurs outils sur {formatNumber(c.considered)} ·{" "}
        <strong>{formatNumber(c.corroborated_total)}</strong> machine(s) signalée(s) par au moins deux outils ·{" "}
        {c.incidents.automatic} incident(s) créé(s) automatiquement sur {c.incidents.opened} ouvert(s).
      </p>
      <div className="grid-2 stats-inner">
        <div>
          <h3>Alertes calculées</h3>
          <table>
            <thead>
              <tr>
                <th>Corrélation</th>
                <th className="num">Alertes</th>
                <th className="num">Ouvertes</th>
                <th className="num">Faux positifs</th>
              </tr>
            </thead>
            <tbody>
              {c.derived.map((d) => (
                <tr key={d.rule_id}>
                  <td><span className="mono">{d.rule_id}</span> {d.label}</td>
                  <td className="num">{d.total ? <Link to={alertsLink({ rule_id: d.rule_id })}>{formatNumber(d.total)}</Link> : 0}</td>
                  <td className="num">{formatNumber(d.open)}</td>
                  <td className="num"><Rate value={d.fp_rate} closed={d.closed} /></td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3 className="stats-subhead">Dernières chaînes et IP partagées</h3>
          {c.recent.length ? (
            <ul className="plain-list">
              {c.recent.map((r) => (
                <li key={r.id}>
                  <span className={`sev-dot sev-bg-${r.severity}`} title={SEVERITY_LABEL[r.severity]} />
                  <Link to={`/alerts/${r.id}`}>{r.title}</Link>{" "}
                  <span className="muted small">
                    {r.why} · {formatShort(r.created_at)} · {STATUS_LABEL[r.status] ?? r.status}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">Aucune chaîne d'attaque ni IP partagée sur la période.</p>
          )}
        </div>
        <div>
          <h3>Machines corroborées</h3>
          <table>
            <thead>
              <tr><th>Machine</th><th>Outils</th><th className="num">Alertes</th></tr>
            </thead>
            <tbody>
              {c.corroborated_hosts.map((h) => (
                <tr key={h.host}>
                  <td><Link to={`/assets/host/${encodeURIComponent(h.host)}`} className="mono">{h.host}</Link></td>
                  <td className="small">{h.tools.map(moduleLabel).join(", ")}</td>
                  <td className="num">{formatNumber(h.alerts)}</td>
                </tr>
              ))}
              {!c.corroborated_hosts.length && <tr><td colSpan={3} className="muted">Aucune machine signalée par deux outils.</td></tr>}
            </tbody>
          </table>
          <h3 className="stats-subhead">Réponse</h3>
          <ul className="plain-list">
            <li>
              <Link to="/blocks"><strong>{formatNumber(b.total)}</strong> blocage(s) d'IP</Link> ({formatNumber(b.ips)} adresse(s),{" "}
              {b.from_alert} depuis une alerte) : {b.active} actif(s), {b.expired} levé(s) à expiration, {b.removed_manual} levé(s)
              par une personne{b.failed ? <>, <span className="text-bad">{b.failed} en échec</span></> : null}.
            </li>
            <li>
              <strong>{formatNumber(iso.requested)}</strong> demande(s) d'isolement de poste
              {iso.failed ? <> dont <span className="text-bad">{iso.failed} en échec</span></> : null}, {iso.released} levée(s) d'isolement
              {iso.hosts.length > 0 && <span className="muted small"> · {iso.hosts.join(", ")}</span>}.
            </li>
          </ul>
        </div>
      </div>
      <Method lines={c.method} />
    </Card>
  );
}

export default function Stats() {
  const [params, setParams] = useSearchParams();
  const period = params.get("period") ?? "30d";
  const from = params.get("from") ?? "";
  const to = params.get("to") ?? "";
  const [view, setView] = useState<"severity" | "tool">("severity");
  const range = useMemo(() => bounds(period, from, to), [period, from, to]);
  const { data, error, loading } = usePolling(
    () => api<Analytics>(`/analytics${query({ since: range.since.toISOString(), until: range.until.toISOString() })}`),
    [range.since.getTime(), range.until.getTime()],
    0,
  );

  const update = (changes: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(changes)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    setParams(next);
  };
  const choosePeriod = (value: string) => {
    if (value === "custom") {
      const r = bounds(period, from, to);
      const last = new Date(r.until.getTime() - 1);
      update({ period: value, from: from || localDay(r.since), to: to || localDay(last) });
    } else update({ period: value, from: "", to: "" });
  };

  // Liens vers la liste des alertes : même période (jours entiers), tous statuts sauf précision
  const fromDay = localDay(range.since);
  const toDay = localDay(new Date(range.until.getTime() - 1));
  const alertsLink = (extra: Record<string, string> = {}) =>
    `/alerts${query({ status: "", period: "custom", from: fromDay, to: toDay, ...extra })}`;

  const v = data?.volumes;
  const q = data?.quality;
  const d = data?.delays;
  const m = data?.mitre;

  return (
    <>
      <PageHeader title="Statistiques" icon={ChartNoAxesCombined}
        subtitle="Volumes, sources, qualité des détections, délais, MITRE ATT&CK, corrélation et activité horaire">
        <div className="segmented" role="group" aria-label="Période">
          {PERIODS.map((p) => (
            <button key={p.value} type="button" className={period === p.value ? "active" : ""}
              onClick={() => choosePeriod(p.value)}>
              {p.label}
            </button>
          ))}
        </div>
        {period === "custom" && (
          <>
            <input type="date" value={from} max={to || undefined} aria-label="Du"
              onChange={(e) => update({ from: e.target.value })} />
            <input type="date" value={to} min={from || undefined} aria-label="Au"
              onChange={(e) => update({ to: e.target.value })} />
          </>
        )}
      </PageHeader>
      <p className="muted">
        Périmètre : alertes <strong>créées</strong> du {new Date(range.since).toLocaleString("fr-FR")} au{" "}
        {new Date(range.until).toLocaleString("fr-FR")}, comparées à la période précédente de même durée. Chaque bloc
        détaille sa méthode de calcul ; les chiffres soulignés ouvrent la liste des alertes correspondantes (alertes
        actives sur ces jours, la liste peut donc en contenir quelques-unes créées juste avant).
      </p>
      <ErrorBanner error={error} />
      {loading && !data && <p className="muted">Calcul en cours…</p>}

      {data && v && q && d && m && (
        <>
          <div className="report-tiles">
            <Link to={alertsLink()} className="report-tile">
              <strong>{formatNumber(v.total)}</strong>
              <span>alertes créées</span>
              <small className="muted">
                {v.delta_pct === null ? "période précédente sans alerte" : `${v.delta_pct >= 0 ? "+" : ""}${v.delta_pct} %`}
                {" "}vs période précédente ({formatNumber(v.previous_total)})
              </small>
            </Link>
            <Link to={alertsLink({ status: "false_positive" })} className="report-tile">
              <strong>{q.fp_rate === null ? "—" : `${q.fp_rate} %`}</strong>
              <span>de faux positifs</span>
              <small className="muted">{formatNumber(q.false_positive)} sur {formatNumber(q.closed)} alertes clôturées</small>
            </Link>
            <div className="report-tile">
              <strong>{duration(d.acknowledge.all.median)}</strong>
              <span>prise en charge (médiane)</span>
              <small className="muted">90 % en moins de {duration(d.acknowledge.all.p90)} · n = {d.acknowledge.all.count}</small>
            </div>
            <div className="report-tile">
              <strong>{duration(d.close_human.all.median)}</strong>
              <span>clôture par une personne (médiane)</span>
              <small className="muted">90 % en moins de {duration(d.close_human.all.p90)} · n = {d.close_human.all.count}</small>
            </div>
            <Link to="/alerts" className="report-tile">
              <strong>{formatNumber(d.backlog_total)}</strong>
              <span>alertes ouvertes aujourd'hui</span>
              <small className="muted">{formatNumber(d.backlog[3]?.total ?? 0)} depuis plus de 30 jours</small>
            </Link>
            <Link to="/incidents" className="report-tile">
              <strong>{formatNumber(d.incidents.opened)}</strong>
              <span>incident(s) ouvert(s)</span>
              <small className="muted">{d.incidents.closed} clos sur la période</small>
            </Link>
          </div>

          <Card title="Volumes d'alertes" icon={ChartNoAxesCombined}>
            <div className="stats-toolbar">
              <span className="muted">
                {formatNumber(v.total)} alertes regroupant {formatNumber(v.occurrences)} occurrences ·{" "}
                {v.granularity === "day" ? "par jour" : "par semaine"}
                {v.by_category.length > 0 && (
                  <> · {v.by_category.map((c) => `${c.label} ${formatNumber(c.count)}`).join(", ")}</>
                )}
              </span>
              <div className="segmented" role="group" aria-label="Découpage">
                <button type="button" className={view === "severity" ? "active" : ""} onClick={() => setView("severity")}>
                  Par sévérité
                </button>
                <button type="button" className={view === "tool" ? "active" : ""} onClick={() => setView("tool")}>
                  Par outil
                </button>
              </div>
            </div>
            {view === "severity" ? (
              <StackedBars
                buckets={v.timeline.map((t) => t.bucket)}
                granularity={v.granularity}
                series={(["info", "low", "medium", "high", "critical"] as Severity[]).map((s) => ({
                  key: s, label: SEVERITY_LABEL[s], className: `fill-${s}`, values: v.timeline.map((t) => t[s]),
                }))}
              />
            ) : (
              <StackedBars
                buckets={v.tool_series.buckets}
                granularity={v.granularity}
                series={Object.entries(v.tool_series.series).map(([tool, values], i) => ({
                  key: tool, label: tool === "autres" ? "Autres outils" : moduleLabel(tool),
                  className: TOOL_CLASSES[Math.min(i, TOOL_CLASSES.length - 1)], values,
                }))}
              />
            )}
            <div className="grid-2 stats-inner">
              <div>
                <h3>Par outil</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Outil</th>
                      <th className="num">Alertes</th>
                      {BY_SEVERITY.map((s) => <th key={s} className="num">{SEVERITY_LABEL[s]}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {v.by_tool.map((t) => (
                      <tr key={t.module}>
                        <td>{t.module.startsWith("(") ? t.module : moduleLabel(t.module)}</td>
                        <td className="num">
                          {t.module.startsWith("(") ? formatNumber(t.total)
                            : <Link to={alertsLink({ module: t.module })}>{formatNumber(t.total)}</Link>}
                        </td>
                        {BY_SEVERITY.map((s) => <td key={s} className={`num ${t[s] ? "" : "muted"}`}>{formatNumber(t[s])}</td>)}
                      </tr>
                    ))}
                    {!v.by_tool.length && <tr><td className="muted" colSpan={7}>Aucune alerte sur la période.</td></tr>}
                  </tbody>
                </table>
              </div>
              <div>
                <h3>Règles les plus actives</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Règle</th>
                      <th className="num">Alertes</th>
                      <th className="num" title="Répétitions regroupées dans ces alertes">Occurrences</th>
                      <th>Sévérité max.</th>
                    </tr>
                  </thead>
                  <tbody>
                    {v.by_rule.slice(0, 12).map((r) => (
                      <tr key={r.rule_id}>
                        <td title={r.tools.map(moduleLabel).join(", ")}>
                          <span className="mono">{r.rule_id}</span> {r.rule_name}
                        </td>
                        <td className="num"><Link to={alertsLink({ rule_id: r.rule_id })}>{formatNumber(r.total)}</Link></td>
                        <td className="num muted">{formatNumber(r.occurrences)}</td>
                        <td><span className={`badge sev-${r.severity}`}>{SEVERITY_LABEL[r.severity]}</span></td>
                      </tr>
                    ))}
                    {!v.by_rule.length && <tr><td className="muted" colSpan={4}>Aucune alerte sur la période.</td></tr>}
                  </tbody>
                </table>
              </div>
            </div>
            <Method lines={v.method} />
          </Card>

          <SourcesCard s={data.sources} error={data.events_error} />

          <DisksCard d={data.disks} />

          <Card title="Qualité des détections" icon={Gauge}>
            <p>
              <strong>{formatNumber(q.closed)}</strong> alertes clôturées sur {formatNumber(q.total)} ({formatNumber(q.open)} encore
              ouvertes) : {formatNumber(q.resolved)} résolues, <strong>{formatNumber(q.false_positive)}</strong> faux positifs. Clôturées
              par une personne {formatNumber(q.closed_by.human)}, par le Mini-SOC {formatNumber(q.closed_by.system)}, par
              l'outil d'origine {formatNumber(q.closed_by.source)}.
              {Object.keys(q.verdicts).length > 0 && (
                <> Qualification automatique : {(Object.entries(q.verdicts) as [keyof typeof VERDICT_LABEL, number][])
                  .map(([k, n]) => `${VERDICT_LABEL[k]} ${formatNumber(n)}`).join(", ")}.</>
              )}
            </p>
            {q.noisy_rules.length > 0 && (
              <div className="stats-callout">
                <TriangleAlert size={16} />
                <span>
                  Règle(s) bruyante(s) à régler :{" "}
                  {q.noisy_rules.map((r, i) => (
                    <Fragment key={r.rule_id}>
                      {i > 0 && ", "}
                      <Link to={alertsLink({ rule_id: r.rule_id, status: "false_positive" })}>{r.rule_id}</Link> ({r.fp_rate} % sur {r.closed})
                    </Fragment>
                  ))}
                </span>
              </div>
            )}
            <div className="grid-2 stats-inner">
              <div>
                <h3>Par règle</h3>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Règle</th>
                        <th className="num">Alertes</th>
                        <th className="num">Ouvertes</th>
                        <th className="num">Faux positifs</th>
                        <th className="num" title="Clôtures : personne / automatique (Mini-SOC + outil)">Clôture pers./auto</th>
                      </tr>
                    </thead>
                    <tbody>
                      {q.by_rule.slice(0, 15).map((r) => (
                        <tr key={r.rule_id} className={r.noisy ? "stats-noisy" : undefined}>
                          <td><span className="mono">{r.rule_id}</span> {r.rule_name}</td>
                          <td className="num"><Link to={alertsLink({ rule_id: r.rule_id })}>{formatNumber(r.total)}</Link></td>
                          <td className="num">{formatNumber(r.open)}</td>
                          <td className="num"><Rate value={r.fp_rate} closed={r.closed} /></td>
                          <td className="num muted">{r.closed_by.human} / {r.closed_by.system + r.closed_by.source}</td>
                        </tr>
                      ))}
                      {!q.by_rule.length && <tr><td className="muted" colSpan={5}>Aucune alerte sur la période.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
              <div>
                <h3>Par outil</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Outil</th>
                      <th className="num">Alertes</th>
                      <th className="num">Ouvertes</th>
                      <th className="num">Faux positifs</th>
                      <th className="num">Clôture pers./auto</th>
                    </tr>
                  </thead>
                  <tbody>
                    {q.by_tool.map((t) => (
                      <tr key={t.module}>
                        <td>{t.module.startsWith("(") ? t.module : moduleLabel(t.module)}</td>
                        <td className="num">{formatNumber(t.total)}</td>
                        <td className="num">{formatNumber(t.open)}</td>
                        <td className="num"><Rate value={t.fp_rate} closed={t.closed} /></td>
                        <td className="num muted">{t.closed_by.human} / {t.closed_by.system + t.closed_by.source}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            <Method lines={q.method} />
          </Card>

          <Card title="Délais de traitement" icon={Timer}>
            <div className="grid-2 stats-inner">
              <div>
                <h3>Par sévérité</h3>
                <table>
                  <thead>
                    <tr>
                      <th rowSpan={2}>Sévérité</th>
                      <th className="num" colSpan={3}>Prise en charge</th>
                      <th className="num" colSpan={3}>Clôture par une personne</th>
                    </tr>
                    <tr>
                      <th className="num">Médiane</th><th className="num">P90</th><th className="num">n</th>
                      <th className="num">Médiane</th><th className="num">P90</th><th className="num">n</th>
                    </tr>
                  </thead>
                  <tbody>
                    {BY_SEVERITY.map((s) => (
                      <tr key={s}>
                        <td><span className={`badge sev-${s}`}>{SEVERITY_LABEL[s]}</span></td>
                        <DistCell d={d.acknowledge[s]} />
                        <DistCell d={d.close_human[s]} />
                      </tr>
                    ))}
                    <tr className="stats-total">
                      <td>Toutes</td>
                      <DistCell d={d.acknowledge.all} />
                      <DistCell d={d.close_human.all} />
                    </tr>
                  </tbody>
                </table>
                <p className="muted small">
                  Clôtures automatiques, à part : Mini-SOC {d.close_system.count} (médiane {duration(d.close_system.median)}), outil
                  d'origine {d.close_source.count} (médiane {duration(d.close_source.median)}). {d.never_acknowledged_open} alerte(s) de
                  la période encore ouverte(s) sans prise en charge.
                </p>
              </div>
              <div>
                <h3>Évolution</h3>
                <MedianLines points={d.timeline} granularity={d.granularity} />
              </div>
            </div>
            <div className="grid-2 stats-inner">
              <div>
                <h3>Alertes ouvertes aujourd'hui, par ancienneté</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Ancienneté</th>
                      <th className="num">Total</th>
                      {BY_SEVERITY.map((s) => <th key={s} className="num">{SEVERITY_LABEL[s]}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {d.backlog.map((b) => (
                      <tr key={b.age}>
                        <td>{b.label}</td>
                        <td className="num"><strong>{formatNumber(b.total)}</strong></td>
                        {BY_SEVERITY.map((s) => <td key={s} className={`num ${b[s] ? "" : "muted"}`}>{formatNumber(b[s])}</td>)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div>
                <h3>Incidents</h3>
                <p>
                  <strong>{d.incidents.opened}</strong> ouvert(s) sur la période ({d.incidents.still_open} pas encore clos),{" "}
                  <strong>{d.incidents.closed}</strong> clos sur la période.
                </p>
                <table>
                  <thead>
                    <tr>
                      <th>Délai</th><th className="num">Médiane</th><th className="num">P90</th><th className="num">n</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr><td>Jusqu'à « maîtrisé »</td><DistCell d={d.incidents.time_to_contain} /></tr>
                    <tr><td>Jusqu'à la clôture</td><DistCell d={d.incidents.time_to_close} /></tr>
                  </tbody>
                </table>
                {d.incidents.by_category.length > 0 && (
                  <p className="muted small">
                    {d.incidents.by_category.map((c) => `${INCIDENT_CATEGORY[c.category] ?? c.category} ${c.count}`).join(" · ")}
                  </p>
                )}
              </div>
            </div>
            <Method lines={d.method} />
          </Card>

          <Card title="MITRE ATT&CK et cibles" icon={Target}>
            <div className="grid-2 stats-inner">
              <div>
                <h3>Tactiques observées (ordre de la chaîne d'attaque)</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Tactique</th>
                      <th className="num" title="Alertes dont c'est l'unique tactique possible">Certaines</th>
                      <th className="num" title="Alertes dont c'est l'une des tactiques possibles">Possibles</th>
                      <th className="stats-bar-col" />
                      <th className="num">Règles</th>
                      <th className="num">Entités</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(() => {
                      const max = Math.max(1, ...m.tactics.map((t) => t.alerts));
                      return m.tactics.map((t) => (
                        <tr key={t.id} className={t.alerts ? undefined : "muted"}>
                          <td><span className="mono small">{t.id}</span> {t.name}</td>
                          <td className="num"><strong>{formatNumber(t.exclusive)}</strong></td>
                          <td className="num">{formatNumber(t.alerts)}</td>
                          <td className="stats-bar-col">
                            <span className="stats-double">
                              <Bar value={t.alerts} max={max} className="stats-possible" />
                              <Bar value={t.exclusive} max={max} className="stats-certain" />
                            </span>
                          </td>
                          <td className="num">{formatNumber(t.rules)}</td>
                          <td className="num">{formatNumber(t.entities)}</td>
                        </tr>
                      ));
                    })()}
                  </tbody>
                </table>
              </div>
              <div>
                <h3>Techniques des règles déclenchées</h3>
                <table>
                  <thead>
                    <tr><th>Technique</th><th className="num">Alertes</th><th>Règles</th></tr>
                  </thead>
                  <tbody>
                    {m.techniques.map((t) => (
                      <tr key={t.id}>
                        <td title={t.tactics.join(", ")}>
                          <a href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`} target="_blank"
                            rel="noopener noreferrer" className="mono">{t.id}</a> {t.name}
                          {t.tactics.length > 1 && <span className="muted small"> · {t.tactics.length} tactiques</span>}
                        </td>
                        <td className="num">{formatNumber(t.alerts)}</td>
                        <td className="small">{t.rules.join(", ")}</td>
                      </tr>
                    ))}
                    {!m.techniques.length && <tr><td className="muted" colSpan={3}>Aucune technique rattachée.</td></tr>}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="stats-grid-3 stats-inner">
              {[
                { title: "Machines les plus citées", rows: m.hosts.map((h) => ({ key: h.name, label: h.name, to: `/assets/host/${encodeURIComponent(h.name)}`, r: h })) },
                { title: "Comptes les plus cités", rows: m.accounts.map((a) => ({ key: a.name, label: a.name, to: `/assets/account/${encodeURIComponent(a.name)}`, r: a })) },
                { title: "Adresses IP publiques", rows: m.ips.map((i) => ({ key: i.ip, label: i.ip, to: alertsLink({ q: i.ip }), r: i })) },
              ].map((block) => (
                <div key={block.title}>
                  <h3>{block.title}</h3>
                  <table>
                    <thead>
                      <tr><th>Nom</th><th className="num">Alertes</th><th>Outils</th></tr>
                    </thead>
                    <tbody>
                      {block.rows.map(({ key, label, to, r }) => (
                        <tr key={key}>
                          <td>
                            <span className={`sev-dot sev-bg-${r.severity}`} title={`Sévérité max. : ${SEVERITY_LABEL[r.severity]}`} />
                            <Link to={to} className="mono">{label}</Link>
                          </td>
                          <td className="num">{formatNumber(r.alerts)}</td>
                          <td className="small muted">{r.tools.map((t) => (t.startsWith("(") ? t : moduleLabel(t))).join(", ")}</td>
                        </tr>
                      ))}
                      {!block.rows.length && <tr><td className="muted" colSpan={3}>Aucune.</td></tr>}
                    </tbody>
                  </table>
                </div>
              ))}
            </div>
            <Method lines={m.method} />
          </Card>

          <CorrelationCard c={data.correlation} alertsLink={alertsLink} />
          <HeatmapCard h={data.heatmap} error={data.events_error} />
        </>
      )}
      {data && !data.volumes.total && <Empty>Aucune alerte créée sur cette période.</Empty>}
    </>
  );
}
