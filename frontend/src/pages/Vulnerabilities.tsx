import { Bug, ExternalLink, Search as SearchIcon, ShieldAlert } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, query } from "../api";
import { CritDot } from "../components/Hosts";
import { ToolBadge } from "../components/AlertBits";
import { TrivyCveCard, TrivySources, type TrivyCve } from "../components/Trivy";
import { WordPressSites } from "../components/WordPress";
import { Card, Empty, ErrorBanner, PageHeader, SeverityBadge, StatusBadge } from "../components/ui";
import { usePolling } from "../hooks";
import { formatDate, formatNumber, timeAgo } from "../labels";
import type { AlertStatus, ImpactedHost, Severity } from "../types";

interface FleetRow {
  cve: string;
  machines: number;
  servers: number;
  prioritized: number;
  score: number | null;
  kev: boolean;
  sample: string[];
}
interface Fleet {
  items: FleetRow[];
  total: number;
  assets: number;
  sources?: { cyberwatch: number; trivy: number };
  at: number | null;
}
interface Machine {
  name: string;
  asset_id: string;
  server: boolean;
  os: string;
  ip: string;
  status: "vulnerable" | "ignored" | "fixed";
  triage?: string;
  prioritized: boolean;
  environmental_score: number | null;
  detected_at: string;
  fixed_at: string;
  comment?: string;
  console: string;
  criticality: ImpactedHost["criticality"] | null;
  owner: string;
  service: string;
}
interface CveDetail {
  cve: string;
  kev: { vendor: string; product: string; name: string; added: string; due: string; ransomware: boolean; description: string } | null;
  certfr: { kind: string; title: string; link: string; date: string }[];
  cyberwatch: {
    configured: boolean;
    live: boolean;
    known?: boolean;
    error?: string;
    info: {
      description: string;
      score: number | null;
      level: string;
      epss: number | null;
      published: string;
      exploitable: boolean | null;
      exploit_code_maturity: string;
      euvd_id: string;
      technologies: string[];
      certfr: { code: string; link: string }[];
    } | null;
  };
  machines: Machine[];
  trivy: TrivyCve[];
  counts: { vulnerable: number; ignored: number; fixed: number };
  detections: { module: string; target: string; rule: string; count: number; first: string; last: string }[];
  alerts: { id: number; title: string; status: AlertStatus; severity: number; rule_id: string; last_seen: string | null }[];
  ninjaone: { available: boolean; reason: string };
}

const SEV: Severity[] = ["info", "low", "medium", "high", "critical"];
const STATUS: Record<Machine["status"], string> = { vulnerable: "vulnérable", ignored: "écartée (triage)", fixed: "corrigée" };
const pct = (v: number | null) => (v == null ? "—" : `${(v * 100).toFixed(v < 0.01 ? 2 : 1)} %`);

function CveSearch({ initial = "" }: { initial?: string }) {
  const [value, setValue] = useState(initial);
  const navigate = useNavigate();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const code = value.trim().toUpperCase();
    if (code) navigate(`/cve/${encodeURIComponent(code)}`);
  };
  return (
    <form onSubmit={submit} className="cve-search">
      <SearchIcon size={16} />
      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="CVE-2024-3400"
        aria-label="Numéro de CVE"
        pattern="[Cc][Vv][Ee]-\d{4}-\d{4,7}"
        title="Format CVE-AAAA-NNNN"
        autoFocus
      />
      <button type="submit">Chercher</button>
    </form>
  );
}

function FleetView() {
  const [kevOnly, setKevOnly] = useState(false);
  const [filter, setFilter] = useState("");
  const { data, error } = usePolling(() => api<Fleet>(`/cve${query({ kev_only: kevOnly ? "true" : undefined, limit: 300 })}`), [kevOnly], 300000);
  const rows = (data?.items ?? []).filter((r) => !filter || `${r.cve} ${r.sample.join(" ")}`.toLowerCase().includes(filter.toLowerCase()));
  return (
    <>
      <ErrorBanner error={error} />
      <TrivySources />
      <WordPressSites />
      <Card title="CVE présentes sur le parc (Cyberwatch, Trivy)" icon={Bug}>
        {!data?.at ? (
          <Empty>Pas encore de relevé Cyberwatch ni de rapport Trivy (Intégrations). La recherche ci-dessus fonctionne quand même pour la veille et les détections.</Empty>
        ) : (
          <>
            <div className="filters">
              <label className="inline">
                <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} /> Failles activement exploitées (KEV) seulement
              </label>
              <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filtrer (CVE, machine)" />
              <span className="spacer" />
              <span className="muted small">
                {formatNumber(data.total)} CVE distinctes sur {data.assets} actifs
                {data.sources?.trivy ? ` (dont ${data.sources.trivy} source(s) Trivy)` : ""} · relevé {timeAgo(new Date(data.at * 1000).toISOString())}
              </span>
            </div>
            <table>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th className="num">Machines</th>
                  <th className="num">dont serveurs</th>
                  <th className="num">Prioritaire sur</th>
                  <th className="num">Score</th>
                  <th>Exemples</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.cve}>
                    <td>
                      <Link to={`/cve/${r.cve}`} className="mono">{r.cve}</Link>
                      {r.kev && <span className="kev-tag">KEV</span>}
                    </td>
                    <td className="num">{r.machines}</td>
                    <td className="num">{r.servers}</td>
                    <td className="num">{r.prioritized || "—"}</td>
                    <td className="num">{r.score ?? "—"}</td>
                    <td className="muted small">{r.sample.join(", ")}{r.machines > r.sample.length ? "…" : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {rows.length === 0 && <Empty>Aucune CVE ne correspond.</Empty>}
          </>
        )}
      </Card>
    </>
  );
}

function DetailView({ code }: { code: string }) {
  const { data, error, loading } = usePolling(() => api<CveDetail>(`/cve/${encodeURIComponent(code)}`), [code], 0);
  if (loading && !data) return <p className="muted">Recherche de {code}…</p>;
  if (!data) return <ErrorBanner error={error} />;
  const cw = data.cyberwatch;
  const info = cw.info;
  return (
    <>
      <ErrorBanner error={error} />
      <div className="cve-head">
        <h2 className="mono">{data.cve}</h2>
        {data.kev && <span className="kev-tag big">Activement exploitée (CISA KEV){data.kev.ransomware ? " · rançongiciels" : ""}</span>}
        {info?.level && <span className="muted">gravité {info.level}{info.score != null ? ` (${info.score})` : ""}</span>}
        {info?.epss != null && <span className="muted" title="Probabilité d'exploitation dans les 30 jours (EPSS)">EPSS {pct(info.epss)}</span>}
      </div>

      <div className="report-tiles parc-tiles">
        <div className="report-tile">
          <strong className={data.counts.vulnerable ? "text-bad" : "text-good"}>{data.counts.vulnerable}</strong>
          <span>machine(s) vulnérable(s)</span>
          <small className="muted">{data.machines.filter((m) => m.status === "vulnerable" && m.server).length} serveur(s)</small>
        </div>
        <div className="report-tile">
          <strong>{data.counts.fixed}</strong>
          <span>corrigée(s)</span>
        </div>
        <div className="report-tile">
          <strong>{data.counts.ignored}</strong>
          <span>écartée(s) au triage</span>
        </div>
        <div className="report-tile">
          <strong>{data.detections.length}</strong>
          <span>détection(s) qui la citent</span>
          <small className="muted">90 derniers jours</small>
        </div>
      </div>

      <Card title="Machines touchées" icon={ShieldAlert}>
        {!cw.configured ? (
          <Empty>
            Cyberwatch n'est pas raccordé : pas de CVE par machine du parc
            {data.trivy?.length ? " (images Docker et serveurs analysés par Trivy : ci-dessous)." : "."}
          </Empty>
        ) : (
          <>
            {!cw.live && (
              <p className="muted small">
                Cyberwatch injoignable ({cw.error}) : liste tirée du dernier relevé (sans l'historique des corrections).
              </p>
            )}
            {cw.live && cw.known === false && <p className="muted small">CVE inconnue de Cyberwatch : aucune machine concernée d'après ses analyses.</p>}
            {data.machines.length ? (
              <table>
                <thead>
                  <tr>
                    <th>Machine</th>
                    <th>État</th>
                    <th>Système</th>
                    <th>Détectée</th>
                    <th>Corrigée</th>
                    <th className="num">Score contextuel</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {data.machines.map((m) => (
                    <tr key={`${m.asset_id}-${m.name}`} className={m.status === "fixed" ? "muted" : ""}>
                      <td>
                        <div className="asset-name">
                          <span>
                            <CritDot host={{ name: m.name, count: 0, rules: [], criticality: m.criticality ?? undefined }} />
                            <Link to={`/assets/host/${encodeURIComponent(m.name)}`} className="mono" title={m.name}>{m.name}</Link>
                          </span>
                          {m.server && <span className="role-tag role-service">serveur</span>}
                        </div>
                        {(m.owner || m.service) && <div className="muted small">{[m.owner, m.service].filter(Boolean).join(" · ")}</div>}
                      </td>
                      <td className={m.status === "vulnerable" ? "text-bad" : m.status === "fixed" ? "text-good" : ""} title={m.comment || m.triage || ""}>
                        {STATUS[m.status]}
                        {m.prioritized && m.status === "vulnerable" && <span className="small"> · prioritaire</span>}
                      </td>
                      <td className="small">{m.os || "—"}</td>
                      <td className="small">{m.detected_at ? formatDate(m.detected_at) : "—"}</td>
                      <td className="small">{m.fixed_at ? formatDate(m.fixed_at) : "—"}</td>
                      <td className="num">{m.environmental_score ?? "—"}</td>
                      <td>
                        {m.console && (
                          <a href={m.console} target="_blank" rel="noopener noreferrer" className="console-link" title="Ouvrir dans Cyberwatch">
                            <ExternalLink size={14} />
                          </a>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              cw.known !== false && <Empty>Aucune machine concernée.</Empty>
            )}
          </>
        )}
        {!data.ninjaone.available && <p className="muted small">NinjaOne : {data.ninjaone.reason}</p>}
      </Card>
      <TrivyCveCard rows={data.trivy ?? []} />

      <div className="grid-2">
        <Card title="La faille">
          {data.kev && (
            <p>
              <strong>{data.kev.vendor} {data.kev.product}</strong> : {data.kev.name}. Ajoutée au catalogue KEV le {data.kev.added}
              {data.kev.due ? `, correction exigée des administrations américaines avant le ${data.kev.due}` : ""}.
            </p>
          )}
          {info?.description && <p className="small">{info.description}</p>}
          {info && (
            <p className="muted small">
              {info.published && `Publiée le ${formatDate(info.published)}`}
              {info.exploit_code_maturity && ` · maturité de l'exploit : ${info.exploit_code_maturity}`}
              {info.euvd_id && ` · ${info.euvd_id}`}
              {info.technologies.length > 0 && ` · ${info.technologies.join(", ")}`}
            </p>
          )}
          {!data.kev && !info && data.trivy?.[0]?.title && <p>{data.trivy[0].title} <span className="muted small">(Trivy)</span></p>}
          {!data.kev && !info && !data.trivy?.[0]?.title && <Empty>Ni Cyberwatch ni le catalogue KEV ne décrivent cette CVE.</Empty>}
          {(data.certfr.length > 0 || (info?.certfr.length ?? 0) > 0) && (
            <ul className="small">
              {data.certfr.map((c) => (
                <li key={c.link}><a href={c.link} target="_blank" rel="noopener noreferrer">{c.title}</a> ({formatDate(c.date)})</li>
              ))}
              {info?.certfr.filter((a) => !data.certfr.some((c) => c.link.includes(a.code))).map((a) => (
                <li key={a.code}><a href={a.link} target="_blank" rel="noopener noreferrer">{a.code}</a></li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Détections et alertes qui la citent">
          {data.detections.length === 0 && data.alerts.length === 0 ? (
            <Empty>Aucune détection (EDR, IPS…) ni alerte ne cite cette CVE sur 90 jours.</Empty>
          ) : (
            <>
              {data.alerts.length > 0 && (
                <ul className="plain-list">
                  {data.alerts.map((a) => (
                    <li key={a.id}>
                      <SeverityBadge severity={SEV[a.severity] ?? "info"} /> <StatusBadge status={a.status} />{" "}
                      <Link to={`/alerts/${a.id}`}>{a.title}</Link> <span className="muted small">{timeAgo(a.last_seen)}</span>
                    </li>
                  ))}
                </ul>
              )}
              {data.detections.length > 0 && (
                <table>
                  <thead>
                    <tr>
                      <th>Outil</th>
                      <th>Machine / adresse</th>
                      <th>Détection</th>
                      <th className="num">Nb</th>
                      <th>Dernière</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.detections.map((d) => (
                      <tr key={`${d.module}-${d.target}-${d.rule}`}>
                        <td><ToolBadge module={d.module} /></td>
                        <td className="mono small">{d.target || "—"}</td>
                        <td className="small">{d.rule}</td>
                        <td className="num">{d.count}</td>
                        <td className="small">{formatDate(d.last)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </Card>
      </div>
    </>
  );
}

/** Recherche par CVE : machines touchées (Cyberwatch), veille, détections et alertes. */
export default function Vulnerabilities() {
  const { code } = useParams();
  return (
    <>
      <PageHeader
        title="Vulnérabilités"
        icon={Bug}
        subtitle={code ? <Link to="/cve">← CVE présentes sur le parc</Link> : "Chercher une CVE : machines touchées, veille, détections qui la citent."}
      >
        <CveSearch key={code} initial={code ?? ""} />
      </PageHeader>
      {code ? <DetailView code={code.toUpperCase()} /> : <FleetView />}
    </>
  );
}
