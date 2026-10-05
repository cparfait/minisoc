import { Download, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { api } from "../api";
import { useUser } from "../App";
import { usePolling } from "../hooks";
import { formatDate, formatNumber } from "../labels";
import { Card, ErrorBanner } from "./ui";

interface ArchiveRow {
  day: string;
  events: number;
  size: number;
  sha256: string;
  prev_hash: string;
  chain_hash: string;
  created_at: string | null;
}

const size = (n: number) => (n > 1e9 ? `${(n / 1e9).toFixed(1)} Go` : n > 1e6 ? `${(n / 1e6).toFixed(1)} Mo` : `${Math.ceil(n / 1e3)} Ko`);

/** Archives scellées des événements : une par jour, empreintes chaînées, vérification et téléchargement. */
export default function Archives() {
  const user = useUser();
  const admin = user?.role === "admin";
  const { data, error } = usePolling(() => api<{ items: ArchiveRow[]; head: ArchiveRow | null; total_size: number }>("/archives"), [], 300000);
  const [check, setCheck] = useState<{ checked: number; ok: boolean; broken: { day: string; problems: string[] }[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const verify = async () => {
    setBusy(true);
    setMessage(null);
    try {
      setCheck(await api("/archives/verify", { method: "POST" }));
    } catch (err) {
      setMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Archives scellées des journaux" icon={ShieldCheck}>
      <p className="muted small">
        Chaque nuit, les événements de la veille sont archivés dans un fichier dont l'empreinte SHA-256 est <strong>chaînée</strong> à
        celle de la veille : modifier ou supprimer une archive casse la chaîne. La dernière empreinte part chaque jour dans le
        résumé par e-mail (preuve datée hors de la VM). Utile pour un dépôt de plainte, une enquête ou l'assureur.
      </p>
      <ErrorBanner error={error ?? message} />
      {data?.head ? (
        <p className="small">
          {formatNumber(data.items.length)} journée(s) scellée(s), {size(data.total_size)} ; dernière : <strong>{data.head.day}</strong>, empreinte de
          chaîne <code className="hash">{data.head.chain_hash}</code>
        </p>
      ) : (
        <p className="muted">Aucune archive pour l'instant : la première journée est scellée la nuit suivant la mise en service.</p>
      )}
      {admin && data?.head && (
        <div className="row">
          <button type="button" disabled={busy} onClick={verify}>{busy ? "Vérification…" : "Vérifier toute la chaîne"}</button>
          {check && (
            <span className={check.ok ? "text-good" : "text-bad"}>
              {check.ok ? `Chaîne intègre : ${check.checked} archive(s) vérifiée(s).` : `${check.broken.length} archive(s) en anomalie !`}
            </span>
          )}
        </div>
      )}
      {check && !check.ok && (
        <ul className="text-bad small">
          {check.broken.map((b) => <li key={b.day}>{b.day} : {b.problems.join(" ; ")}</li>)}
        </ul>
      )}
      {data && data.items.length > 0 && (
        <div className="table-scroll">
          <table className="small archives-table">
            <thead>
              <tr><th>Journée (UTC)</th><th className="num">Événements</th><th className="num">Taille</th><th>Empreinte du fichier</th><th>Scellée</th><th /></tr>
            </thead>
            <tbody>
              {data.items.slice(0, 60).map((a) => (
                <tr key={a.day}>
                  <td className="nowrap">{a.day}</td>
                  <td className="num">{formatNumber(a.events)}</td>
                  <td className="num">{size(a.size)}</td>
                  <td><code className="hash" title={`Chaîne : ${a.chain_hash}\nPrécédente : ${a.prev_hash}`}>{a.sha256.slice(0, 16)}…</code></td>
                  <td className="nowrap">{a.created_at ? formatDate(a.created_at) : "—"}</td>
                  <td>
                    {admin && (
                      <a className="console-link" href={`/api/archives/${a.day}/download`} title="Télécharger (tracé dans le journal d'audit)">
                        <Download size={14} />
                      </a>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
