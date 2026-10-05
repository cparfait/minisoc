import { useMemo, useState, type FormEvent } from "react";
import { api } from "../api";

const inDays = (days: number) => new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);

/**
 * Exception pré-remplie à partir d'une alerte (faux positif connu) : règle, champ et valeur de l'entité.
 * Option : clôturer l'alerte en « Faux positif » avec la justification comme commentaire.
 */
export default function ExceptionFromAlert({ alertId, ruleId, entityKey, onDone }: {
  alertId: number;
  ruleId: string;
  entityKey: string;
  onDone: () => void;
}) {
  const parts = useMemo(
    () => entityKey.split(" | ").map((p) => p.split("=", 2)).filter(([f, v]) => f && v && !f.startsWith("*")),
    [entityKey],
  );
  const [open, setOpen] = useState(false);
  const [choice, setChoice] = useState(0);
  const [scope, setScope] = useState(ruleId);
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState(inDays(90));
  const [close, setClose] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!parts.length) return null;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const [field, value] = parts[choice];
    try {
      await api("/exceptions", {
        method: "POST",
        body: { rule_id: scope, field, value, reason, expires_at: new Date(`${expires}T23:59:59`).toISOString() },
      });
      if (close) {
        await api(`/alerts/${alertId}`, {
          method: "PATCH",
          body: { status: "false_positive", comment: `Faux positif, exception créée jusqu'au ${expires} : ${reason}` },
        });
      }
      setOpen(false);
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <button type="button" onClick={() => setOpen(true)}>
        Créer une exception (faux positif)
      </button>
    );
  }

  return (
    <form className="exception-inline stack" onSubmit={submit}>
      <div className="row">
        <label>
          Ne plus alerter quand
          <select value={choice} onChange={(e) => setChoice(Number(e.target.value))}>
            {parts.map(([f, v], i) => (
              <option key={f} value={i}>{f} = {v}</option>
            ))}
          </select>
        </label>
        <label>
          Pour
          <select value={scope} onChange={(e) => setScope(e.target.value)}>
            <option value={ruleId}>la règle {ruleId}</option>
            <option value="*">toutes les règles</option>
          </select>
        </label>
        <label>
          Jusqu'au
          <input type="date" value={expires} min={inDays(1)} max={inDays(365)} onChange={(e) => setExpires(e.target.value)} />
        </label>
      </div>
      <label>
        Justification (obligatoire)
        <input value={reason} onChange={(e) => setReason(e.target.value)} minLength={10} required
          placeholder="Ex. : poste du service informatique, scanner de vulnérabilités validé par…" />
      </label>
      <label className="checkbox">
        <input type="checkbox" checked={close} onChange={(e) => setClose(e.target.checked)} />
        Clôturer cette alerte en « Faux positif »
      </label>
      {error && <p className="form-error">{error}</p>}
      <div className="row">
        <button type="submit" className="primary" disabled={busy || reason.trim().length < 10}>Créer l'exception</button>
        <button type="button" className="link" onClick={() => setOpen(false)}>Annuler</button>
      </div>
    </form>
  );
}
