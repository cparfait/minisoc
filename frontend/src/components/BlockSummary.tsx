import { ShieldCheck, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";
import { formatDate, timeAgo } from "../labels";
import type { EventRow } from "../types";
import { Card } from "./ui";

interface HostLine {
  name: string;
  count: number;
  last: string;
  blocked: number;
  failed: number;
  threats: Set<string>;
}

/** Une ligne par poste : combien de détections, dernière heure, et si la menace a été neutralisée. */
function byHost(events: EventRow[]): HostLine[] {
  const lines = new Map<string, HostLine>();
  for (const e of events) {
    const name = e.host_name || "poste inconnu";
    const line = lines.get(name) ?? { name, count: 0, last: e.ts, blocked: 0, failed: 0, threats: new Set<string>() };
    line.count += 1;
    if (e.ts > line.last) line.last = e.ts;
    if (e.outcome === "failure") line.failed += 1;
    else line.blocked += 1;
    if (e.threat_name) line.threats.add(e.threat_name);
    lines.set(name, line);
  }
  return [...lines.values()].sort((a, b) => b.failed - a.failed || b.last.localeCompare(a.last));
}

/** Fiche des blocages Bitdefender : quelle menace, combien de postes, bloquée ou non, et quoi faire. */
export default function BlockSummary({ events, massive, total }: { events: EventRow[]; massive: boolean; total?: number }) {
  const malware = events.filter((e) => e.module === "bitdefender" && e.category === "malware");
  if (!malware.length) return null;
  const hosts = byHost(malware);
  const failed = hosts.filter((h) => h.failed > 0).length;
  const threats = [...new Set(malware.map((e) => e.threat_name).filter(Boolean))];
  const first = malware.reduce((a, e) => (e.ts < a ? e.ts : a), malware[0].ts);
  const last = malware.reduce((a, e) => (e.ts > a ? e.ts : a), malware[0].ts);
  const Icon = failed ? ShieldAlert : ShieldCheck;

  return (
    <Card title="Menace détectée par Bitdefender" icon={Icon}>
      <p className={`block-verdict ${failed ? "bad" : "good"}`}>
        {failed ? (
          <>
            <strong>{failed} poste(s) où la menace n'a PAS été neutralisée</strong> sur {hosts.length} touché(s) : à traiter en priorité.
          </>
        ) : (
          <>
            <strong>Bloquée sur les {hosts.length} poste(s) touché(s)</strong> : Bitdefender a neutralisé la menace (supprimée, bloquée ou mise en
            quarantaine).
          </>
        )}
      </p>
      <dl className="coverage-facts">
        <dt>Menace</dt>
        <dd>{threats.length ? threats.slice(0, 5).map((t) => <span key={t} className="badge sev-medium">{t}</span>) : "nom non communiqué"}</dd>
        <dt>Postes touchés</dt>
        <dd>{massive && total && total > hosts.length ? total : hosts.length}</dd>
        <dt>Période</dt>
        <dd>{formatDate(first)} → {formatDate(last)} ({malware.length} détection(s))</dd>
      </dl>
      {massive && (
        <p className="cross-hint">
          Même menace sur plusieurs postes : campagne (e-mail, clé USB, partage) ou test d'intrusion. Comparer avec le calendrier du pentest ; si
          ce n'est pas annoncé, chercher le point commun entre les postes et isoler les plus exposés.
        </p>
      )}
      <div className="table-scroll">
        <table className="assets-table">
          <thead>
            <tr>
              <th>Poste</th>
              <th>État</th>
              <th>Détections</th>
              <th>Dernière</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((h) => (
              <tr key={h.name}>
                <td><Link to={`/assets/host/${encodeURIComponent(h.name)}`}>{h.name}</Link></td>
                <td>
                  {h.failed > 0 ? <span className="badge sev-critical">Non neutralisée</span> : <span className="badge sev-low">Bloquée</span>}
                </td>
                <td className="num">{h.count}</td>
                <td className="nowrap" title={formatDate(h.last)}>{timeAgo(h.last)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {events.length >= 50 && <p className="muted small">Détail limité aux 50 premières détections conservées sur l'alerte : d'autres postes peuvent être touchés.</p>}
    </Card>
  );
}
