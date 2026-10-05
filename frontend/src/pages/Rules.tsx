import { FileUp, History, ListChecks, Trash2, X } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { canEdit, useUser } from "../App";
import { Card, ErrorBanner, MitreTags, PageHeader, SeverityBadge } from "../components/ui";
import { usePolling } from "../hooks";
import { formatDate, formatNumber } from "../labels";
import type { MitreTechnique, Rule, Severity } from "../types";

const TYPE_LABEL: Record<string, string> = {
  match: "Correspondance",
  threshold: "Seuil",
  sequence: "Séquence",
  absence: "Absence",
  novelty: "Nouveauté",
};

interface Tactic {
  id: string;
  name: string;
  techniques: (MitreTechnique & { rules: string[]; tool_hits: number; covered_by: "rules" | "tools" | "both" })[];
}

interface Replay {
  rule_id: string;
  days: number;
  events: number;
  alerts: number;
  entities: number;
  first_seen: string | null;
  last_seen: string | null;
  top: { entity: string; count: number; peak: number; first_seen: string; last_seen: string }[];
  by_day: { day: string; count: number }[];
  sample: Record<string, string>[];
}

interface Conversion {
  ok: boolean;
  title: string;
  level: string;
  rule_id: string | null;
  severity: string | null;
  mitre: string[];
  errors: string[];
  warnings: string[];
  exists: boolean;
}

function ReplayPanel({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const [days, setDays] = useState(30);
  const [result, setResult] = useState<Replay | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (d: number) => {
    setDays(d);
    setBusy(true);
    setError(null);
    try {
      setResult(await api<Replay>(`/rules/${encodeURIComponent(rule.id)}/replay`, { method: "POST", body: { days: d } }));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };
  const max = Math.max(1, ...(result?.by_day.map((d) => d.count) ?? [1]));
  return (
    <Card title={`Rejeu de ${rule.id} : ${rule.name}`} icon={History} className="replay-card">
      <button type="button" className="icon-button close" aria-label="Fermer" onClick={onClose}><X size={16} /></button>
      <p className="muted small">Ce que la règle aurait détecté sur l'historique, sans créer d'alerte ni de notification.</p>
      <div className="segmented" role="group">
        {[7, 30, 90, 365].map((d) => (
          <button key={d} type="button" className={days === d && result ? "active" : ""} disabled={busy} onClick={() => run(d)}>
            {d} jours
          </button>
        ))}
      </div>
      <ErrorBanner error={error} />
      {busy && <p className="muted">Rejeu en cours…</p>}
      {result && !busy && (
        <>
          <div className="replay-kpis">
            <div><strong>{formatNumber(result.alerts)}</strong><span>alertes environ</span></div>
            <div><strong>{formatNumber(result.entities)}</strong><span>entités distinctes</span></div>
            <div><strong>{formatNumber(result.events)}</strong><span>{rule.type === "threshold" ? "événements dans les fenêtres" : "événements concernés"}</span></div>
          </div>
          {result.alerts === 0 ? (
            <p className="text-good">Aucune détection sur {result.days} jours : la règle n'aurait rien signalé (bruit nul, ou situation jamais rencontrée).</p>
          ) : (
            <>
              <div className="replay-days" title="Événements par jour">
                {result.by_day.map((d) => (
                  <div key={d.day} title={`${d.day} : ${d.count}`} style={{ height: `${Math.max(4, (d.count / max) * 100)}%` }} />
                ))}
              </div>
              <table className="small">
                <thead><tr><th>Entité</th><th className="num">{rule.type === "threshold" ? "Fenêtres" : "Événements"}</th><th>Première</th><th>Dernière</th></tr></thead>
                <tbody>
                  {result.top.map((t) => (
                    <tr key={t.entity}>
                      <td className="mono">{t.entity}</td>
                      <td className="num">{formatNumber(t.count)}</td>
                      <td>{formatDate(t.first_seen)}</td>
                      <td>{formatDate(t.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {result.sample.length > 0 && (
                <details>
                  <summary className="small">Derniers événements concernés</summary>
                  <ul className="small mono">
                    {result.sample.map((s, i) => (
                      <li key={i}>{formatDate(s.ts)} · {s.host_name || s.user_name || s.source_ip} · {s.rule_name} · {String(s.message).slice(0, 140)}</li>
                    ))}
                  </ul>
                </details>
              )}
            </>
          )}
        </>
      )}
    </Card>
  );
}

function SigmaImport({ admin, onDone }: { admin: boolean; onDone: () => void }) {
  const [text, setText] = useState("");
  const [preview, setPreview] = useState<Conversion[] | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setMessage(null);
    try {
      await fn();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };
  const ok = preview?.filter((c) => c.ok).length ?? 0;
  return (
    <Card title="Importer des règles Sigma" icon={FileUp}>
      <p className="muted small">
        Sigma est le format ouvert des règles de détection (des milliers de règles publiques, dépôt SigmaHQ). Seules les règles
        dont <strong>tous les champs</strong> correspondent aux journaux collectés sont converties : journaux de sécurité Windows,
        Microsoft 365, pare-feu. Les règles sur les processus, fichiers ou registre relèvent de l'EDR (HarfangLab les applique
        déjà) et sont refusées avec la raison. Les règles importées sont <strong>désactivées</strong> : rejouez-les sur
        l'historique avant de les activer.
      </p>
      <textarea rows={8} className="mono" value={text} onChange={(e) => { setText(e.target.value); setPreview(null); }}
        placeholder={"title: …\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4720\n  condition: selection\nlevel: medium\n---\n(plusieurs règles séparées par ---)"} />
      <div className="row">
        <label className="ghost small file-pick">
          Fichiers .yml
          <input type="file" accept=".yml,.yaml" multiple onChange={async (e) => {
            const files = [...(e.target.files ?? [])];
            setText((await Promise.all(files.map((f) => f.text()))).join("\n---\n"));
            setPreview(null);
          }} />
        </label>
        <button type="button" disabled={busy || !text.trim()} onClick={() => run(async () => {
          setPreview((await api<{ items: Conversion[] }>("/rules/sigma/preview", { method: "POST", body: { text } })).items);
        })}>Aperçu de la conversion</button>
        {admin && preview && ok > 0 && (
          <button type="button" className="primary" disabled={busy} onClick={() => run(async () => {
            const r = await api<{ imported: string[]; updated: string[]; refused: unknown[] }>("/rules/sigma", { method: "POST", body: { text, enable: false } });
            setMessage({ ok: true, text: `${r.imported.length} règle(s) importée(s) (désactivées), ${r.updated.length} mise(s) à jour, ${r.refused.length} refusée(s).` });
            setPreview(null);
            setText("");
            onDone();
          })}>Importer {ok} règle(s)</button>
        )}
      </div>
      {message && <p className={message.ok ? "text-good" : "text-bad"}>{message.text}</p>}
      {preview && (
        <ul className="sigma-preview">
          {preview.map((c, i) => (
            <li key={i} className={c.ok ? "ok" : "ko"}>
              <strong>{c.ok ? "✔" : "✘"} {c.title}</strong>
              {c.ok && (
                <span className="muted small">
                  {" "}→ {c.rule_id} · {c.severity}{c.mitre.length > 0 && ` · ${c.mitre.join(", ")}`}{c.exists && " · déjà importée (sera mise à jour)"}
                </span>
              )}
              {c.errors.map((e) => <div key={e} className="text-bad small">{e}</div>)}
              {c.warnings.map((w) => <div key={w} className="text-warn small">{w}</div>)}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export default function Rules() {
  const user = useUser();
  const admin = user?.role === "admin";
  const { data, error, reload } = usePolling(() => api<{ items: Rule[] }>("/rules"), [], 0);
  const coverage = usePolling(() => api<{ tactics: Tactic[] }>("/rules/coverage/full"), [], 0);
  const [replaying, setReplaying] = useState<Rule | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const covered = coverage.data?.tactics.filter((t) => t.techniques.length).length ?? 0;
  const act = async (fn: () => Promise<unknown>) => {
    setMessage(null);
    try {
      await fn();
      reload();
      coverage.reload();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <>
      <PageHeader title="Règles de détection" icon={ListChecks} subtitle="Règles, rejeu sur l'historique, import Sigma, couverture MITRE ATT&CK" />
      <ErrorBanner error={error ?? coverage.error ?? message} />

      {coverage.data && (
        <Card title={`Couverture MITRE ATT&CK : ${covered} tactique(s) sur ${coverage.data.tactics.length}`}>
          <div className="coverage-legend small">
            <span><i className="cov-rules" /> règle du Mini-SOC</span>
            <span><i className="cov-tools" /> détectée par un outil (HarfangLab, 90 jours)</span>
            <span><i className="cov-both" /> les deux</span>
          </div>
          <div className="coverage">
            {coverage.data.tactics.map((t) => (
              <div key={t.id} className={`coverage-col ${t.techniques.length ? "covered" : ""}`}>
                <div className="coverage-head">
                  {t.name}
                  <small>{t.id}</small>
                </div>
                {t.techniques.length === 0 ? (
                  <div className="coverage-gap">non couvert</div>
                ) : (
                  t.techniques.map((tech) => (
                    <a key={tech.id} href={tech.url} target="_blank" rel="noopener noreferrer" className={`coverage-cell cov-${tech.covered_by}`}
                      title={[tech.rules.length ? `Règles : ${tech.rules.join(", ")}` : "", tech.tool_hits ? `Outils : ${tech.tool_hits} détection(s)` : ""].filter(Boolean).join("\n")}>
                      <strong>{tech.id}</strong>
                      <span>{tech.name}</span>
                      <small>{[tech.rules.length ? `${tech.rules.length} règle(s)` : "", tech.tool_hits ? `${tech.tool_hits} détection(s)` : ""].filter(Boolean).join(" · ")}</small>
                    </a>
                  ))
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {replaying && <ReplayPanel key={replaying.id} rule={replaying} onClose={() => setReplaying(null)} />}

      {canEdit(user) && <SigmaImport admin={admin} onDone={() => { reload(); coverage.reload(); }} />}

      <p className="muted small">
        Règles « fichier » : YAML versionnés dans <code>backend/rules/</code> (après modification :{" "}
        <code>docker compose exec api python -m minisoc.cli check-rules</code>, puis redémarrer <code>api</code> et <code>worker</code>).
        Règles « Sigma » : importées depuis cette page, stockées en base.
      </p>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Règle</th>
              <th>Type</th>
              <th>Logique</th>
              <th>MITRE ATT&amp;CK</th>
              <th>Sévérité</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {data?.items.map((r) => {
              const sigma = r.file.startsWith("sigma:");
              return (
                <tr key={r.id} className={r.enabled ? "" : "disabled"}>
                  <td className="mono nowrap">
                    <Link to={`/alerts?rule_id=${encodeURIComponent(r.id)}&status=`}>{r.id}</Link>
                    <div><span className={`rule-source ${sigma ? "sigma" : ""}`}>{sigma ? "Sigma" : "fichier"}</span></div>
                  </td>
                  <td>
                    {r.name}
                    {!r.enabled && <span className="muted small"> (désactivée)</span>}
                    <div className="muted small rule-desc">{r.description}</div>
                  </td>
                  <td>{TYPE_LABEL[r.type] ?? r.type}</td>
                  <td className="mono small">
                    {r.condition && <div>{r.condition}</div>}
                    {r.window && <div>fenêtre {r.window}</div>}
                    {r.group_by.length > 0 && <div>par {r.group_by.join(", ")}</div>}
                  </td>
                  <td><MitreTags techniques={r.mitre} /></td>
                  <td>{r.severity === "from_event" ? "selon l'outil" : <SeverityBadge severity={r.severity as Severity} />}</td>
                  <td className="nowrap">
                    {canEdit(user) && (r.type === "match" || r.type === "threshold") && (
                      <button type="button" className="ghost small" title="Rejouer sur l'historique" onClick={() => setReplaying(r)}>
                        <History size={14} /> Rejouer
                      </button>
                    )}
                    {admin && sigma && (
                      <>
                        <label className="switch small" title={r.enabled ? "Désactiver" : "Activer"}>
                          <input type="checkbox" checked={r.enabled} onChange={(e) => act(() => api(`/rules/custom/${encodeURIComponent(r.id)}`, { method: "PATCH", body: { enabled: e.target.checked } }))} />
                          <span />
                        </label>
                        <button type="button" className="icon-button" title="Supprimer la règle importée"
                          onClick={() => window.confirm(`Supprimer ${r.id} ?`) && act(() => api(`/rules/custom/${encodeURIComponent(r.id)}`, { method: "DELETE" }))}>
                          <Trash2 size={14} />
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}
