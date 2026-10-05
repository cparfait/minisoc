import { ExternalLink } from "lucide-react";
import { Fragment, useEffect, useState } from "react";
import { api } from "../api";
import { canEdit, useUser } from "../App";
import { formatDate, moduleLabel } from "../labels";
import type { EventRow } from "../types";
import AIConversation from "./AIConversation";
import { Empty } from "./ui";

/** Renseignement : IP bannie par CrowdSec ou vulnérabilité du catalogue KEV (pas la même chose). */
function IntelTag({ intel }: { intel: string }) {
  if (intel.startsWith("kev:")) return <span className="intel-tag kev" title={`Catalogue CISA KEV : ${intel.slice(4)}`}>KEV</span>;
  return <span className="intel-tag" title={intel}>banni</span>;
}

let aiEnabled: Promise<boolean> | null = null;
const aiReady = () =>
  (aiEnabled ??= api<{ enabled: boolean }>("/ai/status").then((s) => s.enabled).catch(() => false));

function pretty(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

async function copy(text: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  const area = document.createElement("textarea"); // repli hors HTTPS
  area.value = text;
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  document.execCommand("copy");
  area.remove();
}

/** Journal brut d'un événement déplié : copie et analyse par l'IA (si configurée, rôle analyste). */
function EventRaw({ event }: { event: EventRow }) {
  const user = useUser();
  const [ai, setAi] = useState(false);
  const [analyse, setAnalyse] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const text = pretty(event.raw);
  useEffect(() => {
    if (canEdit(user)) aiReady().then(setAi);
  }, [user]);

  const doCopy = async (label: string, value: string) => {
    try {
      await copy(value);
      setCopied(label);
    } catch {
      setCopied("Copie impossible");
    }
    setTimeout(() => setCopied(null), 2000);
  };
  const summary = [
    `Date : ${formatDate(event.ts)}`,
    `Source : ${moduleLabel(event.module)}`,
    event.host_name && `Poste : ${event.host_name}`,
    event.user_name && `Compte : ${event.user_name}`,
    event.source_ip && `IP source : ${event.source_ip}`,
    `Message : ${event.message}`,
  ].filter(Boolean).join("\n") + "\n\n" + text;

  return (
    <div className="event-raw">
      <div className="row event-actions">
        <button type="button" onClick={() => doCopy("Journal brut copié", text)}>Copier le journal brut</button>
        <button type="button" onClick={() => doCopy("Événement copié", summary)}>Copier avec le résumé</button>
        {ai && !analyse && (
          <button type="button" className="primary" onClick={() => setAnalyse(true)}>Analyser avec l'IA</button>
        )}
        {event.reference && (
          <a className="button" href={event.reference} target="_blank" rel="noopener noreferrer">
            Ouvrir dans {moduleLabel(event.module)} <ExternalLink size={14} />
          </a>
        )}
        {copied && <span className="text-good small" role="status">{copied}</span>}
      </div>
      <div className="pre mono">{text}</div>
      {analyse && (
        <div className="event-ai">
          <AIConversation
            path={`/ai/events/${event.event_id}/analyze`}
            initialQuestion="Analyse cet événement : que s'est-il passé, est-ce plausiblement légitime ou malveillant, quelles vérifications concrètes faire et quelle action recommandes-tu ?"
            placeholder="Question complémentaire sur cet événement…"
            autoStart
          />
        </div>
      )}
    </div>
  );
}

const OUTCOME: Record<string, string> = { success: "succès", failure: "échec" };

export default function EventTable({ events }: { events: EventRow[] }) {
  const [open, setOpen] = useState<string | null>(null);
  if (!events.length) return <Empty>Aucun événement.</Empty>;
  const geo = events.some((e) => e.source_country || e.source_as);
  const links = events.some((e) => e.reference);
  const columns = links ? 9 : 8;
  return (
    <>
    <table className="events-table">
      <thead>
        <tr>
          <th>Date</th>
          <th>Source</th>
          <th>Catégorie</th>
          <th>Résultat</th>
          <th>IP source</th>
          <th>Compte</th>
          <th>Poste</th>
          <th>Message</th>
          {links && <th aria-label="Console d'origine" />}
        </tr>
      </thead>
      <tbody>
        {events.map((e) => (
          <Fragment key={e.event_id}>
            <tr className="clickable" onClick={() => setOpen(open === e.event_id ? null : e.event_id)}>
              <td className="nowrap">{formatDate(e.ts)}</td>
              <td>{moduleLabel(e.module)}</td>
              <td>
                {e.category}
                {e.network_service && <span className="muted"> · {e.network_service}</span>}
              </td>
              <td className={e.outcome === "failure" ? "text-bad" : e.outcome === "success" ? "text-good" : ""}>
                {OUTCOME[e.outcome] ?? "—"}
              </td>
              <td className="mono nowrap" title={[e.source_as, e.intel].filter(Boolean).join(" · ")}>
                {e.source_ip || "—"}
                {e.source_country && <span className="geo-tag">{e.source_country}</span>}
                {e.intel && <IntelTag intel={e.intel} />}
              </td>
              <td>{e.user_name || "—"}</td>
              <td>{e.host_name || "—"}</td>
              <td className="ellipsis">{e.message}</td>
              {links && (
                <td>
                  {e.reference && (
                    <a href={e.reference} target="_blank" rel="noopener noreferrer" className="console-link"
                      title={`Ouvrir dans la console ${moduleLabel(e.module)}`} onClick={(ev) => ev.stopPropagation()}>
                      <ExternalLink size={14} />
                    </a>
                  )}
                </td>
              )}
            </tr>
            {open === e.event_id && (
              <tr className="raw-row">
                <td colSpan={columns}>
                  <EventRaw event={e} />
                </td>
              </tr>
            )}
          </Fragment>
        ))}
      </tbody>
    </table>
    {geo && (
      <p className="muted small attribution">
        Géolocalisation : données GeoLite2 créées par MaxMind, disponibles sur{" "}
        <a href="https://www.maxmind.com" target="_blank" rel="noopener noreferrer">https://www.maxmind.com</a>.
      </p>
    )}
    </>
  );
}
