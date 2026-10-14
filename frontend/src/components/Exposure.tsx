import { ChevronDown, ChevronRight, ExternalLink, Globe2, Wrench } from "lucide-react";
import { useState } from "react";
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
  console?: string;
}

const FOLD_KEY = "minisoc.exposure.open";

/** Machines à corriger en premier : vulnérabilités, antivirus, menaces, failles KEV, exposition, criticité.
 * `collapsible` : bloc replié par défaut (une ligne de synthèse), dépliable d'un clic, état mémorisé. */
export default function ExposureTop({ limit = 8, collapsible = false }: { limit?: number; collapsible?: boolean }) {
  const { data } = usePolling(() => api<{ items: ExposureRow[]; ninjaone: boolean; cyberwatch?: boolean }>(`/exposure${query({ limit })}`), [limit], 300000);
  const [open, setOpen] = useState(() => localStorage.getItem(FOLD_KEY) === "1");
  if (collapsible) {
    const items = data?.items ?? [];
    const exposed = items.filter((r) => r.internet_exposed).length;
    const toggle = () => {
      localStorage.setItem(FOLD_KEY, open ? "0" : "1");
      setOpen(!open);
    };
    return (
      <section className={`card exposure-fold ${open ? "is-open" : ""}`}>
        <h2>
          <button type="button" className="fold-toggle" onClick={toggle} aria-expanded={open}>
            {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
            <Wrench size={15} strokeWidth={2} />
            À corriger en priorité
            {!open && data && (
              <span className="fold-summary">
                {items.length === 0
                  ? "rien à corriger"
                  : `${items.length} machine${items.length > 1 ? "s" : ""}${exposed ? ` dont ${exposed} exposée${exposed > 1 ? "s" : ""} à Internet` : ""} · en tête : ${items[0].name}`}
              </span>
            )}
          </button>
        </h2>
        {open && <ExposureBody data={data} />}
      </section>
    );
  }
  return (
    <Card title="À corriger en priorité" icon={Wrench}>
      <ExposureBody data={data} />
    </Card>
  );
}

function ExposureBody({ data }: { data: { items: ExposureRow[]; ninjaone: boolean; cyberwatch?: boolean } | null }) {
  return (
    <>
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
                {r.console && (
                  <a href={r.console} target="_blank" rel="noopener noreferrer" className="console-link" title="Ouvrir dans Cyberwatch">
                    <ExternalLink size={12} />
                  </a>
                )}
                <strong className="exposure-score">{r.score}</strong>
              </div>
              <div className="small">{r.reasons.filter((x) => x.points > 0).slice(0, 3).map((x) => x.label).join(" · ")}</div>
              {r.actions.length > 0 && <div className="small exposure-action">→ {r.actions.slice(0, 2).join(" ; ")}</div>}
            </li>
          ))}
        </ol>
      )}
      {data && !data.ninjaone && !data.cyberwatch && (
        <p className="muted small">
          Sans NinjaOne ni Cyberwatch raccordé, seules les alertes, les failles KEV citées et l'exposition déclarée dans l'inventaire
          sont prises en compte (pas encore les vulnérabilités ni l'antivirus).
        </p>
      )}
    </>
  );
}
