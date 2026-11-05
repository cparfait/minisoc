import { ExternalLink, Ticket } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../api";
import { formatDate, timeAgo } from "../labels";
import type { AlertTicket } from "../types";
import { Fold } from "./ui";

interface View {
  enabled: boolean;
  ticket: AlertTicket | null;
  draft: { subject: string; body: string };
}

/** Lien, état et date de relecture d'un ticket NinjaOne déjà ouvert. */
function TicketState({ ticket }: { ticket: AlertTicket }) {
  return (
    <div className="ticket-state small">
      <div>Ouvert par {ticket.by} le {formatDate(ticket.at)}</div>
      <div className="muted">État relu dans NinjaOne {timeAgo(ticket.checked_at)} (toutes les 5 minutes).</div>
      <a className="button" href={ticket.url} target="_blank" rel="noopener noreferrer">
        Ouvrir le ticket n° {ticket.id} <ExternalLink size={14} />
      </a>
    </div>
  );
}

/** Ticket NinjaOne de l'alerte : son état s'il existe, sinon le formulaire, relu avant l'envoi. */
export default function NinjaTicket({ alertId, ticket, editable, onDone }: {
  alertId: number;
  ticket?: AlertTicket | null;
  editable: boolean;
  onDone: () => Promise<void>;
}) {
  const [view, setView] = useState<View | null>(null);
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<View>(`/response/ticket/${alertId}`).then((v) => {
      setView(v);
      setSubject(v.draft.subject);
      setBody(v.draft.body);
    }).catch(() => setView(null));
  }, [alertId]);

  if (ticket) {
    return (
      <Fold title={`Ticket NinjaOne n° ${ticket.id}`} icon={Ticket} className="rail-fold" hint={ticket.label} defaultOpen>
        <TicketState ticket={ticket} />
      </Fold>
    );
  }
  if (!view?.enabled || !editable) return null;

  const send = async () => {
    setBusy(true);
    setError(null);
    try {
      await api("/response/ticket", { method: "POST", body: { alert_id: alertId, subject: subject.trim(), body: body.trim() } });
      await onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      await onDone(); // l'échec est inscrit dans l'historique de l'alerte
    } finally {
      setBusy(false);
    }
  };

  return (
    <Fold title="Ouvrir un ticket NinjaOne" icon={Ticket} className="rail-fold">
      <div className="stack">
        <label>
          Sujet
          <input value={subject} maxLength={200} onChange={(e) => setSubject(e.target.value)} />
        </label>
        <label>
          Texte envoyé à NinjaOne
          <textarea value={body} rows={7} maxLength={8000} onChange={(e) => setBody(e.target.value)} />
        </label>
        {error && <p className="form-error">{error}</p>}
        <div className="row">
          <button type="button" className="primary" disabled={busy || subject.trim().length < 3 || body.trim().length < 3} onClick={send}>
            {busy ? "Envoi…" : "Ouvrir le ticket"}
          </button>
        </div>
      </div>
    </Fold>
  );
}
