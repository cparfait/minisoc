import { Globe2, Wrench } from "lucide-react";
import { Link } from "react-router-dom";
import { api, query } from "../api";
import { usePolling } from "../hooks";
import { Card, Empty } from "./ui";

interface ExposureRow {
  name: string;
  score: number;
  criticality: string;
  internet_exposed: boolean;
  owner: string;
  service: string;
  reasons: { label: string; points: number }[];
  actions: string[];
  has_posture: boolean;
}

/** Machines à corriger en premier : vulnérabilités, antivirus, menaces, failles KEV, exposition, criticité. */
export default function ExposureTop({ limit = 8 }: { limit?: number }) {
  const { data } = usePolling(() => api<{ items: ExposureRow[]; ninjaone: boolean }>(`/exposure${query({ limit })}`), [limit], 300000);
  return (
    <Card title="À corriger en priorité" icon={Wrench}>
      {!data || data.items.length === 0 ? (
        <Empty>Rien à corriger en priorité.</Empty>
      ) : (
        <ol className="exposure-list">
          {data.items.map((r) => (
            <li key={r.name} title={r.reasons.map((x) => `${x.points ? `+${x.points} ` : ""}${x.label}`).join("\n")}>
              <div className="exposure-head">
                <Link to={`/assets/host/${encodeURIComponent(r.name)}`} className="mono">{r.name}</Link>
                {r.internet_exposed && <span className="exposure-tag"><Globe2 size={11} /> Internet</span>}
                {(r.owner || r.service) && <span className="muted small">{[r.owner, r.service].filter(Boolean).join(" · ")}</span>}
                <strong className="exposure-score">{r.score}</strong>
              </div>
              <div className="small">{r.reasons.filter((x) => x.points > 0).slice(0, 3).map((x) => x.label).join(" · ")}</div>
              {r.actions.length > 0 && <div className="small exposure-action">→ {r.actions.slice(0, 2).join(" ; ")}</div>}
            </li>
          ))}
        </ol>
      )}
      {data && !data.ninjaone && (
        <p className="muted small">
          Sans NinjaOne raccordé, seules les alertes, les failles KEV citées et l'exposition déclarée dans l'inventaire sont prises en
          compte (pas encore les vulnérabilités ni l'antivirus).
        </p>
      )}
    </Card>
  );
}
