import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

interface Status {
  enabled: boolean;
  group: string;
  default_hours: number;
}
interface Result {
  blocked: string[];
  already: string[];
  refused: Record<string, string>;
  failed: Record<string, string>;
}

const DURATIONS = [1, 4, 24, 24 * 7, 24 * 30];
const durationLabel = (h: number) => (h < 24 ? `${h} h` : `${h / 24} jour${h > 24 ? "s" : ""}`);

/** Blocage des IP d'une alerte sur le pare-feu : sélection, aperçu des refus, confirmation explicite. */
export default function BlockPanel({ alertId, title, candidates }: { alertId: number; title: string; candidates: string[] }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [refused, setRefused] = useState<Record<string, string>>({});
  const [hours, setHours] = useState(24);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const ips = useMemo(() => [...new Set(candidates.filter(Boolean))], [candidates]);

  useEffect(() => {
    api<Status>("/response/status").then((s) => {
      setStatus(s);
      setHours(s.default_hours || 24);
    }).catch(() => setStatus(null));
    if (ips.length) {
      api<{ allowed: string[]; refused: Record<string, string> }>("/response/check", {
        method: "POST", body: { ips, reason: "aperçu" },
      }).then((r) => {
        setRefused(r.refused);
        setSelected(new Set(r.allowed));
      }).catch(() => undefined);
    }
  }, [ips]);

  if (!ips.length) return null;
  if (status && !status.enabled) {
    return <p className="muted small">Blocage sur le pare-feu non configuré (Paramètres &gt; Réponse).</p>;
  }

  const toggle = (ip: string) => {
    const next = new Set(selected);
    if (next.has(ip)) next.delete(ip);
    else next.add(ip);
    setSelected(next);
  };

  const run = async () => {
    const list = [...selected];
    if (!window.confirm(`Bloquer ${list.length} adresse(s) IP sur le pare-feu pendant ${durationLabel(hours)} ?\n\nElles seront ajoutées au groupe « ${status?.group} ». Le blocage sera levé automatiquement à l'échéance.`)) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await api<Result>("/response/block", { method: "POST", body: { ips: list, hours, reason: title, alert_id: alertId } }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="block-panel">
      <div className="block-ips">
        {ips.slice(0, 300).map((ip) => (
          <label key={ip} className={`checkbox mono ${refused[ip] ? "disabled" : ""}`} title={refused[ip] ?? ""}>
            <input type="checkbox" disabled={!!refused[ip]} checked={selected.has(ip)} onChange={() => toggle(ip)} />
            {ip}
            {refused[ip] && <small className="muted"> — {refused[ip]}</small>}
          </label>
        ))}
      </div>
      <div className="row">
        <label>
          Durée
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            {[...new Set([...DURATIONS, hours])].sort((a, b) => a - b).map((h) => <option key={h} value={h}>{durationLabel(h)}</option>)}
          </select>
        </label>
        <button className="danger-button" disabled={busy || !selected.size} onClick={run}>
          {busy ? "Blocage…" : `Bloquer ${selected.size} IP sur le pare-feu`}
        </button>
        <Link to="/blocks" className="small">Voir les blocages</Link>
      </div>
      {error && <p className="form-error">{error}</p>}
      {result && (
        <p className={Object.keys(result.failed).length ? "text-bad" : "text-good"}>
          {result.blocked.length} bloquée(s)
          {result.already.length > 0 && `, ${result.already.length} déjà bloquée(s)`}
          {Object.keys(result.refused).length > 0 && `, ${Object.keys(result.refused).length} refusée(s)`}
          {Object.keys(result.failed).length > 0 && ` — échecs : ${Object.values(result.failed)[0]}`}
        </p>
      )}
    </div>
  );
}
