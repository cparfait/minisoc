import { useState } from "react";
import { api } from "../api";
import { WAITING_REASONS, useAssignees } from "./Followup";

/** Actions groupées sur la sélection : assigner, prendre en charge, mettre en attente, clôturer. */
export function BulkActions({ ids, onDone }: { ids: number[]; onDone: () => void }) {
  const assignees = useAssignees();
  const [action, setAction] = useState("");
  const [assignee, setAssignee] = useState("");
  const [reason, setReason] = useState("utilisateur");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const closing = action === "resolved" || action === "false_positive";

  const apply = async () => {
    setBusy(true);
    setMessage(null);
    const body: Record<string, unknown> = { alert_ids: ids, comment: comment.trim() || undefined };
    if (action === "assign") Object.assign(body, { assign: true, assignee: assignee || null });
    else Object.assign(body, { status: action, ...(action === "waiting" ? { waiting_reason: reason } : {}) });
    try {
      const r = await api<{ updated: number }>("/alerts/bulk", { method: "POST", body });
      setMessage({ ok: true, text: `${r.updated} alerte(s) mise(s) à jour.` });
      setAction("");
      setComment("");
      onDone();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bulk-actions">
      <select value={action} onChange={(e) => setAction(e.target.value)} aria-label="Action groupée">
        <option value="">Action…</option>
        <option value="assign">Assigner à…</option>
        <option value="in_progress">Prendre en charge</option>
        <option value="waiting">Mettre en attente</option>
        <option value="resolved">Clôturer (traitée)</option>
        <option value="false_positive">Clôturer (faux positif)</option>
      </select>
      {action === "assign" && (
        <select value={assignee} onChange={(e) => setAssignee(e.target.value)} aria-label="Personne">
          <option value="">— retirer l'assignation —</option>
          {assignees.map((a) => <option key={a.username} value={a.username}>{a.display_name}</option>)}
        </select>
      )}
      {action === "waiting" && (
        <select value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Motif">
          {WAITING_REASONS.map((w) => <option key={w.value} value={w.value}>{w.label}</option>)}
        </select>
      )}
      {action && action !== "assign" && (
        <input placeholder={closing ? "Commentaire (obligatoire)" : "Commentaire (facultatif)"} value={comment}
          onChange={(e) => setComment(e.target.value)} />
      )}
      {action && (
        <button type="button" className="primary" disabled={busy || (closing && !comment.trim())} onClick={apply}>
          {busy ? "…" : "Appliquer"}
        </button>
      )}
      {message && <span className={message.ok ? "text-good small" : "text-bad small"}>{message.text}</span>}
    </div>
  );
}
