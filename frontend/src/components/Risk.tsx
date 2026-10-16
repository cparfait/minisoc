import { Flame, Link2, Monitor, Network, User as UserIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { api, query } from "../api";
import { usePolling } from "../hooks";
import { moduleLabel, timeAgo } from "../labels";
import { Card, Empty } from "./ui";

export interface Contributor {
  points: number;
  alert_id: number;
  title: string;
  rule_id: string;
  severity: number;
  category: string;
  last_seen: string;
}

export interface EntityRisk {
  kind: "host" | "user";
  name: string;
  score: number;
  tactics: { id: string; name: string }[];
  contributors: Contributor[];
  tools?: string[]; // outils de détection l'ayant signalée (menaces)
  corroboration?: number; // points ajoutés quand plusieurs outils la signalent
}

/** Machine ou compte signalé par plusieurs outils indépendants (HarfangLab, Bitdefender, Vectra…). */
function Tools({ risk }: { risk: EntityRisk }) {
  if (!risk.tools || risk.tools.length < 2) return null;
  return (
    <p className="small risk-tools">
      Signalée par {risk.tools.length} outils : {risk.tools.join(", ")} (+{risk.corroboration} points)
    </p>
  );
}

const entityLink = (r: { kind: string; name: string }) =>
  `/assets/${r.kind === "host" ? "host" : "account"}/${encodeURIComponent(r.name)}`;

function ScoreBar({ score, threshold }: { score: number; threshold: number }) {
  const level = score >= 2 * threshold ? "crit" : score >= threshold ? "high" : score >= threshold / 2 ? "mid" : "low";
  return (
    <span className={`risk-bar risk-${level}`} title={`Score ${score} (seuil d'alerte ${threshold})`}>
      <i style={{ width: `${Math.min(100, (score / (2 * threshold)) * 100)}%` }} />
      <b>{score}</b>
    </span>
  );
}

/** Détections qui composent un score, avec leurs points. */
export function Contributors({ items }: { items: Contributor[] }) {
  return (
    <ul className="risk-contributors">
      {items.map((c) => (
        <li key={`${c.alert_id}-${c.title}`}>
          <span className="pts">+{Math.round(c.points)}</span>
          <Link to={`/alerts/${c.alert_id}`}>{c.title}</Link>
          {c.category !== "threat" && <span className="muted small"> ({c.category === "hygiene" ? "hygiène" : "information"})</span>}
          <span className="muted small"> · {timeAgo(c.last_seen)}</span>
        </li>
      ))}
    </ul>
  );
}

/** Accueil : machines et comptes les plus à risque (7 jours). */
export function RiskTop({ limit = 8 }: { limit?: number }) {
  const { data } = usePolling(() => api<{ threshold: number; items: EntityRisk[] }>(`/risk${query({ limit })}`), [limit], 60000);
  return (
    <Card title="Machines et comptes les plus à risque (7 jours)" icon={Flame}>
      {!data || data.items.length === 0 ? (
        <Empty>Aucun risque cumulé.</Empty>
      ) : (
        <ul className="risk-top">
          {data.items.map((r) => (
            <li key={`${r.kind}${r.name}`} title={r.contributors.map((c) => `+${Math.round(c.points)} ${c.title}`).join("\n")}>
              {r.kind === "host" ? <Monitor size={14} /> : <UserIcon size={14} />}
              <Link to={entityLink(r)} className="mono">{r.name}</Link>
              <span className="muted small">
                {r.contributors.length} détection(s){r.tactics.length > 0 && ` · ${r.tactics.length} tactique(s)`}
                {(r.tools?.length ?? 0) > 1 && ` · ${r.tools!.length} outils`}
              </span>
              <ScoreBar score={r.score} threshold={data.threshold} />
            </li>
          ))}
        </ul>
      )}
      <p className="muted small">Au-delà du seuil ({data?.threshold ?? 60} points, Paramètres › Détection), une alerte « risque cumulé » est créée.</p>
    </Card>
  );
}

/** Fiche machine / compte : score et détail. */
export function RiskCard({ kind, name }: { kind: "host" | "account"; name: string }) {
  const { data } = usePolling(() => api<{ threshold: number; risk: EntityRisk | null }>(`/risk/entity${query({ kind, name })}`), [kind, name], 60000);
  return (
    <Card title="Score de risque (7 jours)" icon={Flame}>
      {!data?.risk ? (
        <p className="muted">Aucune détection récente : risque nul.</p>
      ) : (
        <>
          <ScoreBar score={data.risk.score} threshold={data.threshold} />
          {data.risk.tactics.length > 0 && (
            <p className="small">Tactiques MITRE : {data.risk.tactics.map((t) => t.name).join(" → ")}</p>
          )}
          <Tools risk={data.risk} />
          <Contributors items={data.risk.contributors} />
          <p className="muted small">
            Une détection compte une fois ; sévérité, tactiques supplémentaires (+10 chacune), outils supplémentaires
            ayant signalé la même entité (+10 chacun) et criticité de l'inventaire pondèrent le total. Seuil
            d'alerte : {data.threshold}.
          </p>
        </>
      )}
    </Card>
  );
}

interface ChainDetails {
  tactics: string[];
  steps: { alert_id: number; title: string; ts: string; tactics: string[] }[];
}

/** Fiche d'alerte : détail d'une alerte calculée (risque cumulé ou chaîne d'attaque). */
interface SharedIpDetails {
  ip: string;
  tools: string[];
  window_hours: number;
  alerts: { alert_id: number; title: string; rule_id: string; severity: number; modules: string[]; ts: string }[];
}

/** UC-61 : la même adresse IP en alerte sur plusieurs outils. */
function SharedIp({ shared }: { shared: SharedIpDetails }) {
  return (
    <Card title={`${shared.ip} : alertes de ${shared.tools.length} outils en ${shared.window_hours} h`} icon={Network}>
      <p className="small">
        Outils : {shared.tools.map((t) => moduleLabel(t)).join(", ")} ·{" "}
        <Link to={`/events?ip=${encodeURIComponent(shared.ip)}&period=7j`}>tous les événements de cette adresse</Link>
      </p>
      <ol className="chain-steps">
        {shared.alerts.map((a) => (
          <li key={a.alert_id}>
            <span className="muted small">{new Date(a.ts).toLocaleString("fr-FR")}</span>
            <Link to={`/alerts/${a.alert_id}`}>{a.title}</Link>
            <span className="chain-tactics">{a.modules.map((m) => moduleLabel(m)).join(" · ")} · {a.rule_id}</span>
          </li>
        ))}
      </ol>
    </Card>
  );
}

export function DerivedDetails({ details }: { details: Record<string, unknown> }) {
  const risk = details.risk as EntityRisk | undefined;
  const chain = details.chain as ChainDetails | undefined;
  const shared = details.shared_ip as SharedIpDetails | undefined;
  if (shared) return <SharedIp shared={shared} />;
  if (!risk && !chain) return null;
  return (
    <Card title={chain ? "Étapes de la chaîne d'attaque" : "Composition du score de risque"} icon={chain ? Link2 : Flame}>
      {risk && (
        <>
          <p>
            Score <strong>{risk.score}</strong> pour <Link to={entityLink(risk)} className="mono">{risk.name}</Link>
            {risk.tactics.length > 0 && <> · tactiques : {risk.tactics.map((t) => t.name).join(", ")}</>}
          </p>
          <Tools risk={risk} />
          <Contributors items={risk.contributors} />
        </>
      )}
      {chain && (
        <ol className="chain-steps">
          {chain.steps.map((s) => (
            <li key={s.alert_id}>
              <span className="muted small">{new Date(s.ts).toLocaleString("fr-FR")}</span>
              <Link to={`/alerts/${s.alert_id}`}>{s.title}</Link>
              <span className="chain-tactics">{s.tactics.join(" · ")}</span>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}
