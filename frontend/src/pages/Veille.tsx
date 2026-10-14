import { ExternalLink, Radar } from "lucide-react";
import { Link } from "react-router-dom";
import { useState } from "react";
import { api } from "../api";
import CyberwatchExposure from "../components/CyberwatchExposure";
import ParcExposure from "../components/ParcExposure";
import { Card, Empty, ErrorBanner, PageHeader } from "../components/ui";
import { usePolling } from "../hooks";
import { formatDate } from "../labels";

interface KevEntry {
  cve: string;
  vendor: string;
  product: string;
  name: string;
  added: string;
  due: string;
  ransomware: boolean;
  description: string;
}
interface CertItem {
  kind: "alerte" | "avis";
  title: string;
  link: string;
  date: string;
  summary: string;
  cves: string[];
}
interface VeilleData {
  kev: { updated: string | null; count: number; ransomware: number; recent: KevEntry[] };
  certfr: CertItem[];
}

const dateFr = (d: string) => (d ? new Date(d).toLocaleDateString("fr-FR", { timeZone: "Europe/Paris" }) : "—");

export default function Veille() {
  const { data, error } = usePolling(() => api<VeilleData>("/veille"), [], 300000);
  const [filter, setFilter] = useState("");
  const kev = (data?.kev.recent ?? []).filter((k) =>
    !filter || `${k.cve} ${k.vendor} ${k.product} ${k.name}`.toLowerCase().includes(filter.toLowerCase()),
  );

  return (
    <>
      <PageHeader title="Veille" icon={Radar} subtitle="Vulnérabilités activement exploitées (CISA KEV) et CERT-FR" />
      <p className="muted">
        Publications du CERT-FR et catalogue CISA KEV des vulnérabilités activement exploitées, relus automatiquement.
        Toute détection (IPS, EDR) mentionnant une de ces CVE déclenche la règle UC-22.
      </p>
      <ErrorBanner error={error} />
      <ParcExposure />
      <CyberwatchExposure />
      <div className="grid-2">
        <Card title="CERT-FR : alertes et avis récents">
          {data && !data.certfr.length ? (
            <Empty>Flux non encore récupérés (accès Internet du serveur vers cert.ssi.gouv.fr requis).</Empty>
          ) : (
            <ul className="veille-list">
              {data?.certfr.slice(0, 25).map((c) => (
                <li key={c.link}>
                  <span className={`badge ${c.kind === "alerte" ? "sev-critical" : "sev-low"}`}>{c.kind === "alerte" ? "Alerte" : "Avis"}</span>
                  <div>
                    <a href={c.link} target="_blank" rel="noopener noreferrer">{c.title}</a>
                    <div className="muted small">{formatDate(c.date)}{c.cves.length > 0 && ` · ${c.cves.slice(0, 4).join(", ")}${c.cves.length > 4 ? "…" : ""}`}</div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title={`CISA KEV : ${data?.kev.count ?? "…"} vulnérabilités activement exploitées`}>
          <p className="muted small">
            Dont {data?.kev.ransomware ?? "…"} utilisées par des rançongiciels · mis à jour {formatDate(data?.kev.updated)}
          </p>
          <input type="search" placeholder="Filtrer (éditeur, produit, CVE)" value={filter} onChange={(e) => setFilter(e.target.value)} />
          {data && !kev.length ? (
            <Empty>Aucune entrée.</Empty>
          ) : (
            <table className="kev-table">
              <thead>
                <tr>
                  <th>Ajoutée</th>
                  <th>CVE</th>
                  <th>Produit</th>
                </tr>
              </thead>
              <tbody>
                {kev.map((k) => (
                  <tr key={k.cve} title={k.description}>
                    <td className="nowrap">{dateFr(k.added)}</td>
                    <td className="mono nowrap">
                      <Link to={`/cve/${k.cve}`} title="Machines touchées, détections">{k.cve}</Link>{" "}
                      <a href={`https://nvd.nist.gov/vuln/detail/${k.cve}`} target="_blank" rel="noopener noreferrer" className="console-link" title="Fiche NVD">
                        <ExternalLink size={12} />
                      </a>
                      {k.ransomware && <span className="intel-tag">rançongiciel</span>}
                    </td>
                    <td>
                      {k.vendor} {k.product}
                      <div className="muted small">{k.name}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </>
  );
}
