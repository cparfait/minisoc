import { Container, RefreshCw } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { canEdit, useUser } from "../App";
import { usePolling } from "../hooks";
import { formatDate, timeAgo } from "../labels";
import { Card, Empty, ErrorBanner } from "./ui";

export interface TrivySummary {
  key: string;
  name: string;
  host: string;
  local: boolean;
  scanned_at: string;
  received_at: string;
  targets: string[];
  total: number;
  critical: number;
  high: number;
  critical_fixable: number;
  high_fixable: number;
  kev: number;
}
interface LocalStatus {
  service?: { state?: "running" | "ok" | "error"; message?: string; started?: string; finished?: string; updated?: string; errors?: string[]; trivy?: string };
  pending?: boolean;
  problem?: string;
  checked_at?: string;
}
interface Overview {
  enabled: boolean;
  local: LocalStatus;
  sources: TrivySummary[];
}
export interface TrivyCve {
  key: string;
  name: string;
  local: boolean;
  scanned_at: string;
  severity: string;
  score: number | null;
  fixed: boolean;
  title: string;
  pkgs: { target: string; pkg: string; installed: string; fix: string }[];
}
interface Server {
  id: number;
  name: string;
  allowed_ips: string[];
  created_by: string;
  created_at: string | null;
  last_used_at: string | null;
  last_ip: string;
  revoked: boolean;
  report: TrivySummary | null;
}

const SEVERITY: Record<string, string> = { CRITICAL: "critique", HIGH: "haute", MEDIUM: "moyenne", LOW: "basse", UNKNOWN: "inconnue" };

/** État du service minisoc-trivy de la VM, en une phrase. */
function localLine(local: LocalStatus): { text: string; bad: boolean } {
  const s = local.service ?? {};
  if (local.problem) return { text: local.problem, bad: true };
  if (s.state === "running") return { text: `Analyse en cours : ${s.message ?? ""}`, bad: false };
  if (local.pending) return { text: "Analyse demandée : démarrage dans quelques secondes.", bad: false };
  if (s.state === "error") return { text: `Dernière analyse en échec : ${s.message ?? ""} (sudo journalctl -u minisoc-trivy)`, bad: true };
  if (s.state === "ok") {
    const failed = s.errors?.length ? ` ; en échec : ${s.errors.join(", ")}` : "";
    return { text: `Dernière analyse ${timeAgo(s.finished)} : ${s.message ?? ""}${failed}${s.trivy ? ` (Trivy ${s.trivy})` : ""}`, bad: Boolean(s.errors?.length) };
  }
  return { text: "Pas encore d'analyse de la VM (service minisoc-trivy : chaque lundi, après chaque mise à jour, ou à la demande).", bad: false };
}

function ScanButton({ onDone }: { onDone: (text: string, ok: boolean) => void }) {
  const [busy, setBusy] = useState(false);
  return (
    <button type="button" disabled={busy} onClick={async () => {
      setBusy(true);
      try {
        await api("/trivy/scan", { method: "POST" });
        onDone("Analyse demandée : le service de la VM démarre dans les 15 secondes (quelques minutes en tout).", true);
      } catch (err) {
        onDone(err instanceof Error ? err.message : String(err), false);
      } finally {
        setBusy(false);
      }
    }}>
      <RefreshCw size={14} /> Analyser maintenant
    </button>
  );
}

function Counts({ s }: { s: TrivySummary }) {
  return (
    <>
      <td className="num">{s.total}</td>
      <td className={`num ${s.critical_fixable ? "text-bad" : ""}`}>{s.critical_fixable || "—"}</td>
      <td className="num">{s.high_fixable || "—"}</td>
      <td className="num">{s.kev ? <span className="kev-tag">{s.kev} KEV</span> : "—"}</td>
    </>
  );
}

/** Page Vulnérabilités : images de la VM et serveurs analysés par Trivy. */
export function TrivySources() {
  const user = useUser();
  const { data, error, reload } = usePolling(() => api<Overview>("/trivy/overview"), [], 30000);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  if (!data) return <ErrorBanner error={error} />;
  const line = localLine(data.local);
  return (
    <Card title="Images Docker et serveurs (Trivy)" icon={Container}>
      {!data.enabled ? (
        <Empty>Intégration Trivy désactivée (Intégrations › Trivy).</Empty>
      ) : (
        <>
          <div className="filters">
            <span className={`small ${line.bad ? "text-bad" : "muted"}`}>{line.text}</span>
            <span className="spacer" />
            {canEdit(user) && <ScanButton onDone={(text, ok) => { setMessage({ ok, text }); reload(); }} />}
          </div>
          {message && <p className={`small ${message.ok ? "text-good" : "text-bad"}`}>{message.text}</p>}
          {data.sources.length ? (
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Analyse</th>
                  <th className="num">Cibles</th>
                  <th className="num">CVE</th>
                  <th className="num">Critiques corrigeables</th>
                  <th className="num">Hautes corrigeables</th>
                  <th className="num">Activement exploitées</th>
                </tr>
              </thead>
              <tbody>
                {data.sources.map((s) => (
                  <tr key={s.key}>
                    <td>
                      {s.name}
                      {s.local && <span className="role-tag role-service">VM du Mini-SOC</span>}
                      <div className="muted small" title={s.targets.join("\n")}>
                        {s.targets.slice(0, 3).join(", ")}{s.targets.length > 3 ? ` (+${s.targets.length - 3})` : ""}
                      </div>
                    </td>
                    <td className="small" title={formatDate(s.received_at)}>{timeAgo(s.scanned_at)}</td>
                    <td className="num">{s.targets.length}</td>
                    <Counts s={s} />
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>Aucun rapport Trivy reçu pour l'instant.</Empty>
          )}
        </>
      )}
    </Card>
  );
}

/** Fiche d'une CVE : composants touchés dans les images et sur les serveurs, avec la version corrigée. */
export function TrivyCveCard({ rows }: { rows: TrivyCve[] }) {
  if (!rows.length) return null;
  return (
    <Card title="Images Docker et serveurs touchés (Trivy)" icon={Container}>
      <table>
        <thead>
          <tr><th>Source</th><th>Cible</th><th>Composant</th><th>Installé</th><th>Corrigé dans</th><th>Gravité</th></tr>
        </thead>
        <tbody>
          {rows.flatMap((r) => r.pkgs.map((p, i) => (
            <tr key={`${r.key}-${i}`}>
              <td>{i === 0 ? r.name : ""}{i === 0 && r.local && <span className="role-tag role-service">VM</span>}</td>
              <td className="mono small">{p.target}</td>
              <td className="mono small">{p.pkg}</td>
              <td className="mono small">{p.installed || "—"}</td>
              <td className={`mono small ${p.fix ? "text-good" : "muted"}`}>{p.fix || "pas encore de correctif"}</td>
              <td className="small">{i === 0 ? `${SEVERITY[r.severity] ?? r.severity}${r.score != null ? ` (${r.score})` : ""}` : ""}</td>
            </tr>
          )))}
        </tbody>
      </table>
      <p className="muted small">
        Images du Mini-SOC : appliquer le dernier paquet de mise à jour (les images sont reconstruites avec les
        correctifs publiés), une nouvelle analyse suit automatiquement.
      </p>
    </Card>
  );
}

/** Fiche de l'intégration (onglet Configuration) : analyse de la VM, jetons des serveurs, agent. */
export function TrivyAdmin() {
  const overview = usePolling(() => api<Overview>("/trivy/overview"), [], 15000);
  const servers = usePolling(() => api<{ items: Server[] }>("/admin/trivy/servers"), [], 0);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [name, setName] = useState("");
  const [ips, setIps] = useState("");
  const [created, setCreated] = useState<{ name: string; token: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const r = await api<{ name: string; token: string }>("/admin/trivy/servers", {
        method: "POST",
        body: { name, allowed_ips: ips.split(/[\s,;]+/).filter(Boolean) },
      });
      setCreated(r);
      setName("");
      setIps("");
      servers.reload();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };
  const revoke = async (s: Server) => {
    if (!window.confirm(`Révoquer le jeton de ${s.name} ? Ses rapports seront refusés et son dernier état retiré.`)) return;
    try {
      await api(`/admin/trivy/servers/${s.id}`, { method: "DELETE" });
      servers.reload();
      overview.reload();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    }
  };
  const downloadAgent = async () => {
    const res = await fetch("/api/admin/trivy/agent", { credentials: "same-origin" });
    if (!res.ok) {
      setMessage({ ok: false, text: `Téléchargement impossible (HTTP ${res.status})` });
      return;
    }
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = "minisoc-trivy-agent.sh";
    a.click();
    URL.revokeObjectURL(url);
  };

  const line = overview.data ? localLine(overview.data.local) : null;
  const local = overview.data?.sources.find((s) => s.local);
  return (
    <div className="trivy-admin">
      <h3>VM du Mini-SOC</h3>
      {line && <p className={`small ${line.bad ? "text-bad" : "muted"}`}>{line.text}</p>}
      {local && (
        <p className="small">
          {local.targets.length} cible(s), {local.total} CVE dont <strong className={local.critical_fixable ? "text-bad" : ""}>{local.critical_fixable} critique(s) corrigeable(s)</strong>
          {local.kev ? <>, <span className="kev-tag">{local.kev} KEV</span></> : null} · <Link to="/cve">détail sur la page Vulnérabilités</Link>
        </p>
      )}
      <div className="settings-actions">
        <ScanButton onDone={(text, ok) => { setMessage({ ok, text }); overview.reload(); }} />
      </div>

      <h3>Serveurs (agent)</h3>
      <p className="muted small">
        Un jeton par serveur, affiché une seule fois. Installer l'agent sur le serveur avec ce jeton, et l'autoriser
        en 443 vers la VM (sudo minisoc-setup › Entrants › Serveurs Trivy).
      </p>
      {created && (
        <div className="token-once">
          <p><strong>Jeton de {created.name}</strong> (à copier maintenant, il ne sera plus affiché) :</p>
          <code className="mono">{created.token}</code>
          <p className="small">Sur le serveur, en root, avec l'agent téléchargé ci-dessous :</p>
          <code className="mono small">bash minisoc-trivy-agent.sh install {created.token} [/chemin/autorite-minisoc.pem]</code>
        </div>
      )}
      <form className="settings-form" onSubmit={create}>
        <div className="settings-field">
          <label>
            Nom du serveur *
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="srv-docker-01" required maxLength={128} />
          </label>
        </div>
        <div className="settings-field">
          <label>
            Adresses autorisées
            <input value={ips} onChange={(e) => setIps(e.target.value)} placeholder="192.168.10.21 (vide : toutes)" />
          </label>
          <small className="muted">Le jeton n'est accepté que depuis ces adresses ou plages.</small>
        </div>
        <div className="settings-actions">
          <button type="submit" className="primary" disabled={busy || !name.trim()}>Créer le jeton</button>
          <button type="button" onClick={downloadAgent}>Télécharger l'agent (Linux)</button>
        </div>
      </form>
      <ErrorBanner error={servers.error} />
      {servers.data && servers.data.items.length > 0 && (
        <table>
          <thead>
            <tr><th>Serveur</th><th>Adresses</th><th>Dernier rapport</th><th className="num">Critiques corrigeables</th><th /></tr>
          </thead>
          <tbody>
            {servers.data.items.map((s) => (
              <tr key={s.id} className={s.revoked ? "disabled muted" : ""}>
                <td>{s.name}<div className="muted small">créé par {s.created_by} le {formatDate(s.created_at)}</div></td>
                <td className="small">{s.allowed_ips.join(", ") || "toutes"}</td>
                <td className="small">{s.revoked ? "jeton révoqué" : s.last_used_at ? `${timeAgo(s.last_used_at)} depuis ${s.last_ip}` : "jamais"}</td>
                <td className="num">{s.report ? s.report.critical_fixable : "—"}</td>
                <td>{!s.revoked && <button type="button" className="link" onClick={() => revoke(s)}>Révoquer</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {message && <p className={message.ok ? "text-good" : "text-bad"}>{message.text}</p>}
    </div>
  );
}
