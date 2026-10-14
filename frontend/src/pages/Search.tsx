import { BookmarkPlus, ChevronDown, Download, ExternalLink, HelpCircle, Play, Search as SearchIcon, Trash2 } from "lucide-react";
import { Fragment, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { canEdit, useUser } from "../App";
import { ToolBadge } from "../components/AlertBits";
import { EventRaw } from "../components/EventTable";
import Timeline from "../components/Timeline";
import { Card, Empty, ErrorBanner, PageHeader } from "../components/ui";
import { formatDate, formatNumber } from "../labels";
import type { EventRow } from "../types";

const PERIODS = [
  { value: "15m", label: "15 min" },
  { value: "1h", label: "1 heure" },
  { value: "24h", label: "24 heures" },
  { value: "7d", label: "7 jours" },
  { value: "30d", label: "30 jours" },
  { value: "90d", label: "90 jours" },
  { value: "365d", label: "1 an" },
];

const EXAMPLES: { label: string; query: string }[] = [
  { label: "Échecs de connexion par IP", query: "outcome=failure | count by source.ip" },
  { label: "Comptes les plus en échec", query: "outcome=failure | top user.name 10" },
  { label: "Activité d'un compte", query: "user=j.dupont" },
  { label: "Serveurs et détections", query: "host=SRV-* module=harfanglab | count by host.name, rule.name" },
  { label: "Postes par compte", query: "module=windows action=logon | distinct host.name by user.name" },
  { label: "Chronologie d'un mot", query: '"PingCastle" | timeline' },
  { label: "IP hors réseau interne", query: "source.ip!=10.0.0.0/8 source.ip!=192.168.0.0/16 outcome=success | count by source.ip, user.name" },
];

interface Result {
  mode: "events" | "count" | "top" | "distinct" | "timeline";
  columns: string[];
  rows: Record<string, unknown>[];
  events: Record<string, unknown>[];
  total: number | null;
  elapsed_ms: number;
}

interface Saved {
  id: number;
  name: string;
  query: string;
  period: string;
  owner: string;
  shared: boolean;
}

function csv(rows: Record<string, unknown>[], columns: string[]): string {
  const esc = (v: unknown) => {
    const s = v === null || v === undefined ? "" : Array.isArray(v) ? v.join(" ") : String(v);
    return /[";\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [columns.join(";"), ...rows.map((r) => columns.map((c) => esc(r[c])).join(";"))].join("\n");
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob(["﻿" + text], { type: "text/csv;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

/** Valeur d'agrégat → condition de recherche (affinage au clic). */
function condition(field: string, value: unknown): string {
  const v = String(value ?? "");
  return /^[\w.@:\-/]+$/.test(v) && v ? `${field}=${v}` : `${field}="${v.replace(/"/g, '\\"')}"`;
}

export default function Search() {
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState(params.get("q") ?? "");
  const [period, setPeriod] = useState(params.get("period") ?? "24h");
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [help, setHelp] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [saved, setSaved] = useState<Saved[]>([]);
  const user = useUser();

  const loadSaved = useCallback(() => api<{ items: Saved[] }>("/search/saved").then((r) => setSaved(r.items)).catch(() => undefined), []);
  useEffect(() => {
    loadSaved();
  }, [loadSaved]);

  const run = useCallback(async (q: string, p: string) => {
    setBusy(true);
    setError(null);
    setParams(q ? { q, period: p } : { period: p }, { replace: true });
    try {
      setResult(await api<Result>("/search", { method: "POST", body: { query: q, period: p } }));
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [setParams]);

  useEffect(() => {
    if (params.get("q")) run(params.get("q") ?? "", params.get("period") ?? "24h");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const go = (q = query, p = period) => {
    setQuery(q);
    setPeriod(p);
    run(q, p);
  };
  const refine = (field: string, value: unknown) => {
    const [search] = query.split("|");
    go(`${search.trim()} ${condition(field, value)}`.trim());
  };
  const save = async () => {
    const name = window.prompt("Nom de la recherche enregistrée :", query.slice(0, 60));
    if (!name) return;
    const shared = canEdit(user) && window.confirm("La partager avec toute l'équipe ?");
    try {
      await api("/search/saved", { method: "POST", body: { name, query, period, shared } });
      loadSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };
  const exportCsv = () => {
    if (!result) return;
    if (result.mode === "events") {
      const cols = ["ts", "module", "host_name", "user_name", "source_ip", "destination_ip", "action", "outcome", "rule_name", "message"];
      download("recherche-evenements.csv", csv(result.events, cols));
    } else {
      const keys = result.columns.map((c, i) => (result.rows[0] && `g${i}` in result.rows[0] ? `g${i}` : c));
      download("recherche-agregat.csv", csv(result.rows.map((r) => Object.fromEntries(keys.map((k, i) => [result.columns[i], r[k]]))), result.columns));
    }
  };

  const maxCount = result && result.mode !== "events" ? Math.max(1, ...result.rows.map((r) => Number(r.count ?? r.distinct ?? 0))) : 1;

  return (
    <>
      <PageHeader title="Recherche" icon={SearchIcon} subtitle="Interroger tous les journaux, agréger, enquêter" />
      <div className="search-bar">
        <form
          className="search-form"
          onSubmit={(e) => {
            e.preventDefault();
            go();
          }}
        >
          <SearchIcon size={16} />
          <input
            className="mono"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder='ex. user.name=j.dupont outcome=failure | count by source.ip'
            aria-label="Recherche"
            spellCheck={false}
          />
          <select value={period} onChange={(e) => go(query, e.target.value)} aria-label="Période">
            {PERIODS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
          </select>
          <button type="submit" className="primary" disabled={busy}>
            <Play size={14} /> {busy ? "Recherche…" : "Rechercher"}
          </button>
        </form>
        <div className="search-actions">
          <button type="button" className="ghost small" onClick={() => setHelp(!help)}>
            <HelpCircle size={14} /> Syntaxe
          </button>
          <button type="button" className="ghost small" disabled={!query.trim()} onClick={save}>
            <BookmarkPlus size={14} /> Enregistrer
          </button>
          <button type="button" className="ghost small" disabled={!result} onClick={exportCsv}>
            <Download size={14} /> CSV
          </button>
        </div>
      </div>

      {saved.length > 0 && (
        <div className="saved-searches">
          {saved.map((s) => (
            <span key={s.id} className="saved-chip" title={s.query}>
              <button type="button" onClick={() => go(s.query, s.period)}>
                {s.name}
                {s.shared && <small> · équipe</small>}
              </button>
              {(s.owner === user?.username || user?.role === "admin") && (
                <button
                  type="button"
                  aria-label="Supprimer"
                  onClick={() => window.confirm(`Supprimer « ${s.name} » ?`) && api(`/search/saved/${s.id}`, { method: "DELETE" }).then(loadSaved)}
                >
                  <Trash2 size={12} />
                </button>
              )}
            </span>
          ))}
        </div>
      )}

      {help && (
        <Card title="Syntaxe" className="search-help">
          <div className="grid-2">
            <ul className="small">
              <li><code>champ=valeur</code> égalité (sans casse) ; <code>*</code> joker : <code>host=PC-*</code></li>
              <li><code>source.ip=10.0.0.0/8</code> réseau ; <code>!=</code> différent</li>
              <li><code>message~"mot de passe"</code> contient ; <code>!~</code> ne contient pas</li>
              <li><code>source.port&gt;1024</code> comparaisons numériques <code>&gt; &gt;= &lt; &lt;=</code></li>
              <li><code>password</code> ou <code>"texte exact"</code> : texte libre (message et contenu brut)</li>
              <li><code>ET</code> / <code>OU</code> / <code>NON</code> (ou AND, OR, NOT) et parenthèses ; ET implicite</li>
              <li>Raccourcis : <code>ip</code> (source, destination ou machine), <code>user</code>, <code>host</code>, <code>module</code>, <code>outcome</code>, <code>rule</code>, <code>pays</code>…</li>
            </ul>
            <ul className="small">
              <li><code>| count by champ, champ</code> nombre d'événements par valeur</li>
              <li><code>| top champ 10</code> les valeurs les plus fréquentes</li>
              <li><code>| distinct champ by champ</code> nombre de valeurs différentes (ex. postes par compte)</li>
              <li><code>| timeline</code> ou <code>| timeline by champ</code> chronologie</li>
              <li><code>| head 500</code> nombre d'événements affichés (1 000 au plus)</li>
            </ul>
          </div>
          <div className="search-examples">
            {EXAMPLES.map((ex) => (
              <button key={ex.label} type="button" className="ghost small" onClick={() => go(ex.query)} title={ex.query}>
                {ex.label}
              </button>
            ))}
          </div>
        </Card>
      )}

      <ErrorBanner error={error} />

      {!result && !error && (
        <Card>
          <p className="muted">Essayez un exemple :</p>
          <div className="search-examples">
            {EXAMPLES.map((ex) => (
              <button key={ex.label} type="button" className="ghost small" onClick={() => go(ex.query)} title={ex.query}>
                {ex.label}
              </button>
            ))}
          </div>
        </Card>
      )}

      {result && (
        <Card
          title={
            result.mode === "events"
              ? `${formatNumber(result.total ?? 0)} événement(s)${result.total && result.total > result.events.length ? ` · ${formatNumber(result.events.length)} affichés` : ""}`
              : `${formatNumber(result.rows.length)} ligne(s)`
          }
        >
          <p className="muted small search-meta">Réponse en {result.elapsed_ms} ms · recherche tracée dans le journal d'audit</p>
          {result.mode === "events" && result.events.length === 0 && <Empty>Aucun événement.</Empty>}
          {result.mode === "events" && result.events.length > 0 && (
            <div className="table-scroll">
              <table className="search-table">
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Outil</th>
                    <th>Machine</th>
                    <th>Compte</th>
                    <th>Source → destination</th>
                    <th>Action</th>
                    <th>Détection / message</th>
                  </tr>
                </thead>
                <tbody>
                  {result.events.map((e) => {
                    const id = String(e.event_id);
                    return (
                      <Fragment key={id}>
                        <tr className={`clickable ${open === id ? "selected" : ""}`} onClick={() => setOpen(open === id ? null : id)}>
                          <td className="nowrap">{formatDate(String(e.ts))}</td>
                          <td><ToolBadge module={String(e.module)} /></td>
                          <td className="mono">{e.host_name ? <button type="button" className="link" onClick={(ev) => { ev.stopPropagation(); refine("host.name", e.host_name); }}>{String(e.host_name)}</button> : "—"}</td>
                          <td className="mono">{e.user_name ? <button type="button" className="link" onClick={(ev) => { ev.stopPropagation(); refine("user.name", e.user_name); }}>{String(e.user_name)}</button> : "—"}</td>
                          <td className="mono small">{[e.source_ip, e.destination_ip].filter(Boolean).join(" → ") || "—"}</td>
                          <td className="small">{[e.action, e.outcome].filter(Boolean).join(" · ")}</td>
                          <td className="small search-msg">
                            {e.reference ? (
                              <a href={String(e.reference)} target="_blank" rel="noopener noreferrer" className="console-link search-console"
                                title="Ouvrir dans la console de l'outil" onClick={(ev) => ev.stopPropagation()}>
                                <ExternalLink size={13} />
                              </a>
                            ) : null}
                            {e.rule_name ? <strong>{String(e.rule_name)} </strong> : null}
                            {String(e.message ?? "").slice(0, 220)}
                          </td>
                        </tr>
                        {open === id && (
                          <tr className="search-raw">
                            <td colSpan={7}>
                              {/* Même panneau que les autres listes : copie, analyse IA, lien vers la console de l'outil */}
                              <EventRaw event={e as unknown as EventRow} />
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {result.mode === "timeline" && (result.rows.length ? <Timeline rows={result.rows} series={result.columns.length === 3} /> : <Empty>Aucun événement.</Empty>)}
          {result.mode !== "events" && result.mode !== "timeline" && (
            result.rows.length === 0 ? <Empty>Aucun résultat.</Empty> : (
              <div className="table-scroll">
                <table className="search-table agg">
                  <thead>
                    <tr>
                      {result.columns.map((c) => <th key={c} className={c === "count" || c === "distinct" ? "num" : ""}>{c === "count" ? "Nombre" : c === "distinct" ? "Valeurs différentes" : c === "sample" ? "Exemples" : c}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {result.rows.map((r, i) => {
                      const metric = Number(r.count ?? r.distinct ?? 0);
                      return (
                        <tr key={i}>
                          {result.columns.map((c, j) => {
                            const value = r[`g${j}`] ?? r[c];
                            if (c === "count" || c === "distinct") {
                              return (
                                <td key={c} className="num agg-metric">
                                  <span className="agg-bar" style={{ width: `${(metric / maxCount) * 100}%` }} />
                                  <span>{formatNumber(metric)}</span>
                                </td>
                              );
                            }
                            if (c === "sample") return <td key={c} className="small mono">{Array.isArray(r.sample) ? (r.sample as string[]).join(", ") : ""}</td>;
                            return (
                              <td key={c} className="mono">
                                <button type="button" className="link" title="Affiner la recherche sur cette valeur" onClick={() => refine(c, value)}>
                                  {String(value ?? "") || <span className="muted">(vide)</span>}
                                </button>
                              </td>
                            );
                          })}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )
          )}
          {result.mode === "events" && result.events.length > 0 && (
            <p className="muted small"><ChevronDown size={12} /> Cliquer une ligne pour voir le contenu brut ; un nom de machine ou de compte pour affiner.</p>
          )}
        </Card>
      )}
    </>
  );
}
