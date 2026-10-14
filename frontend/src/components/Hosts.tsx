import { ChevronDown, ExternalLink, Monitor, Plus, ScrollText, Server } from "lucide-react";
import { type SyntheticEvent, useRef, useState } from "react";
import { api, query } from "../api";
import { usePolling } from "../hooks";
import { createPortal } from "react-dom";
import { Link } from "react-router-dom";
import { formatNumber } from "../labels";
import type { EventRow, ImpactedHost } from "../types";
import { Card } from "./ui";

const isServer = (name: string) => /^(srv|svr|serveur|dc|ad|fs|sql|web|app|mail|exch)[-_0-9]/i.test(name);
const VISIBLE = 8;

const POPOVER_MAX = 40;

const CRIT_LABEL: Record<string, string> = { vital: "vitale", high: "haute", low: "basse" };

/** Criticité (inventaire) : pastille seulement si elle sort de l'ordinaire. */
export function CritDot({ host }: { host: ImpactedHost }) {
  if (!host.criticality || host.criticality === "normal") return null;
  return <span className={`crit-dot crit-${host.criticality}`} title={`Criticité ${CRIT_LABEL[host.criticality]}`} />;
}

const hostTitle = (h: ImpactedHost) =>
  [h.name, [h.owner, h.service].filter(Boolean).join(" · "), h.criticality && h.criticality !== "normal" ? `criticité ${CRIT_LABEL[h.criticality]}` : "",
    h.rules.join(" · ")].filter(Boolean).join("\n");

function HostChip({ host }: { host: ImpactedHost }) {
  const server = isServer(host.name);
  return (
    <Link to={`/assets/host/${encodeURIComponent(host.name)}`} className={`host-chip ${server ? "server" : ""}`}
      title={hostTitle(host)} onClick={(e) => e.stopPropagation()}>
      {server ? <Server size={11} /> : <Monitor size={11} />}
      {host.name}
      <CritDot host={host} />
    </Link>
  );
}

/** Machines concernées (liste des alertes) : la première (serveurs d'abord), puis « +N » ; la liste complète
 * s'affiche au survol. Le panneau est rendu hors du tableau pour ne pas être rogné par le défilement. */
export function HostChips({ hosts }: { hosts: ImpactedHost[] }) {
  const [rect, setRect] = useState<DOMRect | null>(null);
  const timer = useRef<number | undefined>(undefined);
  if (!hosts.length) return <span className="muted">—</span>;
  const sorted = [...hosts].sort(
    (a, b) => Number(isServer(b.name)) - Number(isServer(a.name)) || b.count - a.count || a.name.localeCompare(b.name),
  );
  const servers = sorted.filter((h) => isServer(h.name)).length;
  const open = (e: SyntheticEvent<HTMLElement>) => {
    window.clearTimeout(timer.current);
    setRect(e.currentTarget.getBoundingClientRect());
  };
  const close = () => {
    timer.current = window.setTimeout(() => setRect(null), 150);
  };
  const keep = () => window.clearTimeout(timer.current);

  return (
    <span className="host-chips">
      <HostChip host={sorted[0]} />
      {sorted.length > 1 && (
        <button type="button" className={`host-chip more ${servers > 1 || (servers === 1 && !isServer(sorted[0].name)) ? "server" : ""}`}
          aria-label={`${sorted.length} machines concernées`} onMouseEnter={open} onMouseLeave={close} onFocus={open} onBlur={close}
          onClick={(e) => e.stopPropagation()}>
          <Plus size={11} />
          {sorted.length - 1}
        </button>
      )}
      {rect &&
        createPortal(
          <div className="host-popover" role="tooltip" onMouseEnter={keep} onMouseLeave={close}
            style={{ top: Math.min(rect.bottom + 6, window.innerHeight - 320), left: Math.max(8, Math.min(rect.left - 120, window.innerWidth - 300)) }}>
            <div className="host-popover-head">
              {sorted.length} machines{servers > 0 && <span> · {servers} serveur(s)</span>}
            </div>
            <ul>
              {sorted.slice(0, POPOVER_MAX).map((h) => (
                <li key={h.name} title={h.rules.join(" · ")}>
                  <HostChip host={h} />
                  <span className="muted small">
                    {[h.owner || h.service, h.count > 1 ? `${formatNumber(h.count)} détections` : ""].filter(Boolean).join(" · ")}
                  </span>
                </li>
              ))}
            </ul>
            {sorted.length > POPOVER_MAX && <div className="muted small">… et {sorted.length - POPOVER_MAX} autres (voir la fiche)</div>}
          </div>,
          document.body,
        )}
    </span>
  );
}

/** Correctifs en attente d'une machine (dernier relevé Cyberwatch). */
interface HostPatches {
  os: string;
  console: string;
  reboot_required: boolean;
  cve_count: number;
  prioritized_count: number;
  kev: string[];
  patches: { product: string; from: string; to: string; patchable: boolean; cves: number; kev: string[]; prioritized: number; max_score: number | null }[];
  patches_total: number;
  known: boolean;
}

/** Ce qu'il faut mettre à jour sur la machine, et pourquoi : produit, version installée → version qui corrige. */
function PatchCell({ info }: { info?: HostPatches }) {
  if (!info) return <span className="muted">—</span>;
  if (!info.known) return <span className="muted small">correctifs relevés au prochain passage de Cyberwatch</span>;
  const rest = info.patches_total - Math.min(3, info.patches.length);
  return (
    <div className="patch-cell">
      {info.reboot_required && <span className="patch-reboot">redémarrage requis</span>}
      {info.patches.length === 0 ? (
        <span className="muted small">aucun correctif en attente</span>
      ) : (
        <ul className="patch-list">
          {info.patches.slice(0, 3).map((p) => (
            <li key={`${p.product}${p.to}`} title={p.kev.length ? `Failles activement exploitées corrigées : ${p.kev.join(", ")}` : undefined}>
              <strong>{p.product}</strong>
              <span className="patch-version mono">{p.from || "?"} → {p.to || "dernière version"}</span>
              <span className="patch-meta">
                {p.cves} CVE
                {p.kev.length > 0 && <b className="patch-kev"> · {p.kev.length} KEV</b>}
                {p.prioritized > 0 && ` · ${p.prioritized} prioritaire${p.prioritized > 1 ? "s" : ""}`}
              </span>
            </li>
          ))}
        </ul>
      )}
      {rest > 0 && (
        <a href={info.console} target="_blank" rel="noopener noreferrer" className="small">
          + {rest} autre{rest > 1 ? "s" : ""} correctif{rest > 1 ? "s" : ""} dans Cyberwatch
        </a>
      )}
    </div>
  );
}

interface Row extends ImpactedHost {
  server: boolean;
  reference?: string;
  events: number;
}

/** Machines concernées par une alerte, en tête de fiche : tableau compact, serveurs d'abord. */
export function ImpactedHosts({ hosts, events }: { hosts: ImpactedHost[]; events: EventRow[] }) {
  const [all, setAll] = useState(false);
  const byHost = new Map<string, { events: number; reference?: string; name: string }>();
  for (const e of events) {
    if (!e.host_name) continue;
    const key = e.host_name.toLowerCase();
    const entry = byHost.get(key) ?? { events: 0, name: e.host_name };
    entry.events += 1;
    entry.reference = entry.reference || e.reference || undefined;
    byHost.set(key, entry);
  }
  const rows: Row[] = hosts.map((h) => {
    const extra = byHost.get(h.name.toLowerCase());
    return { ...h, server: h.asset_type === "serveur" || (!h.asset_type && isServer(h.name)), reference: extra?.reference, events: extra?.events ?? 0 };
  });
  for (const [key, v] of byHost) {
    if (!rows.some((r) => r.name.toLowerCase() === key)) {
      rows.push({ name: v.name, count: 0, rules: [], server: isServer(v.name), reference: v.reference, events: v.events });
    }
  }
  const names = rows.map((r) => r.name).join(",");
  const cyber = usePolling(
    () => (names ? api<{ hosts: Record<string, HostPatches> }>(`/cyberwatch/hosts${query({ names })}`) : Promise.resolve({ hosts: {} as Record<string, HostPatches> })),
    [names],
    0,
  );
  const patches: Record<string, HostPatches> = cyber.data?.hosts ?? {};
  const withPatches = Object.keys(patches).length > 0;
  // Colonne « Détections en cause » inutile quand toutes les machines ont la même (celle du titre de l'alerte)
  const ruleSet = new Set(rows.map((r) => r.rules.join(" · ")));
  const showRules = ruleSet.size > 1;
  if (!rows.length) return null;
  rows.sort((a, b) => Number(b.server) - Number(a.server) || (b.count || b.events) - (a.count || a.events) || a.name.localeCompare(b.name));
  const servers = rows.filter((r) => r.server).length;
  const shown = all ? rows : rows.slice(0, VISIBLE);

  return (
    <Card title={`Machines concernées (${rows.length})`} icon={Monitor} className="impacted-card">
      {servers > 0 && (
        <p className="impacted-warn">
          <Server size={15} /> {servers} serveur(s) touché(s) : à traiter en priorité.
        </p>
      )}
      <table className="impacted-table">
        <thead>
          <tr>
            <th>Machine</th>
            <th>Type</th>
            <th>Criticité</th>
            <th className="num">Détections</th>
            {withPatches && <th>À mettre à jour (Cyberwatch)</th>}
            {showRules && <th>Détections en cause</th>}
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {shown.map((r) => (
            <tr key={r.name} className={r.server ? "server" : ""}>
              <td className="nowrap">
                <span className="impacted-name">
                  {r.server ? <Server size={15} /> : <Monitor size={15} />}
                  <Link to={`/assets/host/${encodeURIComponent(r.name)}`} className="asset-link"><strong className="mono">{r.name}</strong></Link>
                </span>
                {(r.owner || r.service) && <div className="muted small">{[r.owner, r.service].filter(Boolean).join(" · ")}</div>}
              </td>
              <td>{r.server ? <span className="impacted-kind">serveur</span> : <span className="muted small">poste</span>}</td>
              <td>
                {r.criticality && r.criticality !== "normal" ? (
                  <span className={`impacted-kind crit-${r.criticality}`}>{CRIT_LABEL[r.criticality]}</span>
                ) : (
                  <span className="muted small">normale</span>
                )}
              </td>
              <td className="num">{formatNumber(r.count || r.events)}</td>
              {withPatches && <td><PatchCell info={patches[r.name]} /></td>}
              {showRules && <td className="impacted-rules">{r.rules.length ? r.rules.join(" · ") : <span className="muted">—</span>}</td>}
              <td className="impacted-actions">
                <Link to={`/events?host=${encodeURIComponent(r.name)}&period=7d`} className="console-link" title="Événements de la machine (7 jours)">
                  <ScrollText size={14} />
                </Link>
                {r.reference && (
                  <a href={r.reference} target="_blank" rel="noopener noreferrer" className="console-link" title="Ouvrir dans la console d'origine">
                    <ExternalLink size={14} />
                  </a>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > VISIBLE && (
        <button type="button" className="link impacted-more" onClick={() => setAll(!all)}>
          <ChevronDown size={15} className={all ? "flip" : ""} />
          {all ? "Réduire" : `Afficher les ${rows.length - VISIBLE} autres machines`}
        </button>
      )}
    </Card>
  );
}
