import { ExternalLink, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { usePolling } from "../hooks";
import { formatNumber, timeAgo } from "../labels";
import { Card, Empty } from "./ui";

interface TopCve {
  cve: string;
  score: number | null;
  epss: number | null;
  kev: boolean;
  prioritized: boolean;
}
interface Asset {
  id: string;
  name: string;
  server: boolean;
  os: string;
  eol: string;
  eol_passed: boolean;
  cve_count: number;
  prioritized_count: number;
  reboot_required: boolean;
  kev: string[];
  prioritized: string[];
  top: TopCve[];
  console: string;
}
interface Summary {
  at: number | null;
  assets: number;
  servers?: number;
  with_kev?: number;
  kev_cves?: number;
  prioritized?: number;
  with_prioritized?: number;
  eol?: number;
  reboot_required?: number;
  exposed: Asset[];
}

/** Actifs les plus exposés d'après le dernier relevé Cyberwatch (failles KEV présentes, prioritaires, fin de support). */
export default function CyberwatchExposure() {
  const { data } = usePolling(() => api<Summary>("/cyberwatch/summary"), [], 300000);
  if (!data) return null;
  return (
    <Card title="Vulnérabilités : actifs les plus exposés (Cyberwatch)" icon={ShieldAlert}>
      {!data.at ? (
        <Empty>Cyberwatch n'est pas encore raccordé (Intégrations › Cyberwatch).</Empty>
      ) : (
        <>
          <div className="report-tiles parc-tiles">
            <div className="report-tile">
              <strong className={data.with_kev ? "text-bad" : ""}>{data.with_kev ?? 0}</strong>
              <span>actifs avec une faille activement exploitée</span>
              <small className="muted">{data.kev_cves ?? 0} CVE distincte(s) du catalogue KEV</small>
            </div>
            <div className="report-tile">
              <strong>{formatNumber(data.prioritized ?? 0)}</strong>
              <span>vulnérabilités prioritaires</span>
              <small className="muted">sur {data.with_prioritized ?? 0} actif(s)</small>
            </div>
            <div className="report-tile">
              <strong>{data.eol ?? 0}</strong>
              <span>systèmes en fin de support</span>
            </div>
            <div className="report-tile">
              <strong>{data.reboot_required ?? 0}</strong>
              <span>redémarrages requis</span>
            </div>
            <div className="report-tile">
              <strong>{formatNumber(data.assets)}</strong>
              <span>actifs suivis</span>
              <small className="muted">
                {data.servers ?? 0} serveur(s) · relevé {timeAgo(new Date(data.at * 1000).toISOString())}
              </small>
            </div>
          </div>
          {data.exposed.length ? (
            <table>
              <thead>
                <tr>
                  <th>Actif</th>
                  <th>Failles activement exploitées (KEV)</th>
                  <th className="num">Prioritaires</th>
                  <th className="num">CVE</th>
                  <th>Système</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.exposed.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <div className="asset-name">
                        <strong title={a.name}>{a.name}</strong>
                        {a.server && <span className="role-tag role-service">serveur</span>}
                      </div>
                      {a.reboot_required && <div className="muted small">redémarrage requis</div>}
                    </td>
                    <td className={a.kev.length ? "text-bad mono small" : "muted"} title={a.kev.join(", ")}>
                      {a.kev.length ? (
                        <>
                          {a.kev.slice(0, 3).map((c, i) => (
                            <span key={c}>{i > 0 && ", "}<Link to={`/cve/${c}`}>{c}</Link></span>
                          ))}
                          {a.kev.length > 3 && ` (+${a.kev.length - 3})`}
                        </>
                      ) : "—"}
                    </td>
                    <td className="num" title={a.top.filter((c) => c.prioritized).map((c) => `${c.cve}${c.score != null ? ` (${c.score})` : ""}`).join("\n")}>
                      {a.prioritized_count}
                    </td>
                    <td className="num">{formatNumber(a.cve_count)}</td>
                    <td className={a.eol_passed ? "text-bad" : ""} title={a.eol ? `Fin de support : ${new Date(a.eol).toLocaleDateString("fr-FR")}` : ""}>
                      {a.os || "—"}
                      {a.eol_passed && <span className="small"> (fin de support)</span>}
                    </td>
                    <td>
                      {a.console && (
                        <a href={a.console} target="_blank" rel="noopener noreferrer" className="console-link" title="Ouvrir dans Cyberwatch">
                          <ExternalLink size={14} />
                        </a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>Aucun actif exposé au dernier relevé.</Empty>
          )}
        </>
      )}
    </Card>
  );
}
