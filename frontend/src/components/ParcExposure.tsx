import { ExternalLink, HardDrive } from "lucide-react";
import { api } from "../api";
import { usePolling } from "../hooks";
import { formatNumber, timeAgo } from "../labels";
import { Card, Empty } from "./ui";

interface Exposed {
  id: string;
  name: string;
  server: boolean;
  offline: boolean;
  critical: number;
  high: number;
  pending: number;
  failed: number;
  threats: number;
  antivirus: string;
  products: string;
  console: string;
}
interface Summary {
  at: number | null;
  devices: number;
  offline?: number;
  critical?: number;
  high?: number;
  with_critical?: number;
  antivirus_issues?: number;
  threats?: number;
  failed_patches?: number;
  exposed: Exposed[];
}

const AV_LABEL: Record<string, string> = { inactive: "inactif", outdated: "obsolète", ok: "actif", unknown: "—" };

/** Postes les plus exposés d'après le dernier relevé NinjaOne (vulnérabilités, antivirus, menaces). */
export default function ParcExposure() {
  const { data } = usePolling(() => api<Summary>("/ninjaone/posture"), [], 300000);
  if (!data) return null;
  return (
    <Card title="Parc : postes les plus exposés (NinjaOne)" icon={HardDrive}>
      {!data.at ? (
        <Empty>NinjaOne n'est pas encore raccordé (Intégrations › NinjaOne).</Empty>
      ) : (
        <>
          <div className="report-tiles parc-tiles">
            <div className="report-tile">
              <strong>{formatNumber(data.critical ?? 0)}</strong>
              <span>vulnérabilités critiques</span>
              <small className="muted">sur {data.with_critical ?? 0} appareil(s)</small>
            </div>
            <div className="report-tile">
              <strong>{formatNumber(data.high ?? 0)}</strong>
              <span>vulnérabilités élevées</span>
            </div>
            <div className="report-tile">
              <strong>{data.antivirus_issues ?? 0}</strong>
              <span>antivirus coupés ou obsolètes</span>
            </div>
            <div className="report-tile">
              <strong>{data.threats ?? 0}</strong>
              <span>menaces actives</span>
            </div>
            <div className="report-tile">
              <strong>{formatNumber(data.devices)}</strong>
              <span>appareils suivis</span>
              <small className="muted">{data.offline ?? 0} hors ligne · relevé {timeAgo(new Date(data.at * 1000).toISOString())}</small>
            </div>
          </div>
          {data.exposed.length ? (
            <table>
              <thead>
                <tr>
                  <th>Appareil</th>
                  <th className="num">Critiques</th>
                  <th className="num">Élevées</th>
                  <th className="num">Correctifs en attente</th>
                  <th>Antivirus</th>
                  <th className="num">Menaces</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.exposed.map((d) => (
                  <tr key={d.id}>
                    <td>
                      <div className="asset-name">
                        <strong title={d.name}>{d.name}</strong>
                        {d.server && <span className="role-tag role-service">serveur</span>}
                      </div>
                      {d.offline && <div className="muted small">hors ligne</div>}
                    </td>
                    <td className={`num ${d.critical ? "text-bad" : ""}`}>{d.critical}</td>
                    <td className="num">{d.high}</td>
                    <td className="num">
                      {d.pending}
                      {d.failed > 0 && <span className="text-bad small"> ({d.failed} en échec)</span>}
                    </td>
                    <td className={d.antivirus === "inactive" || d.antivirus === "outdated" ? "text-bad" : ""} title={d.products}>
                      {AV_LABEL[d.antivirus] ?? d.antivirus}
                    </td>
                    <td className={`num ${d.threats ? "text-bad" : ""}`}>{d.threats}</td>
                    <td>
                      {d.console && (
                        <a href={d.console} target="_blank" rel="noopener noreferrer" className="console-link" title="Ouvrir dans NinjaOne">
                          <ExternalLink size={14} />
                        </a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>Aucun appareil exposé au dernier relevé.</Empty>
          )}
        </>
      )}
    </Card>
  );
}
