import { useEffect, useState } from "react";
import { api } from "../api";

interface Target {
  edr: string;
  agent_id: string;
  host: string;
  configured: boolean;
}

const EDR_LABEL: Record<string, string> = { harfanglab: "HarfangLab", bitdefender: "Bitdefender" };

/** Isolation réseau d'un poste par l'EDR, avec confirmation par la saisie du nom du poste (F-27). */
export default function IsolationPanel({ alertId, onDone }: { alertId: number; onDone: () => void }) {
  const [data, setData] = useState<{ enabled: boolean; targets: Target[] } | null>(null);
  const [selected, setSelected] = useState<Target | null>(null);
  const [release, setRelease] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    api<{ enabled: boolean; targets: Target[] }>(`/response/isolation/${alertId}`).then(setData).catch(() => setData(null));
  }, [alertId]);

  if (!data || !data.targets.length) return null;

  const submit = async () => {
    if (!selected) return;
    setBusy(true);
    setMessage(null);
    try {
      const r = await api<{ detail: string }>("/response/isolation", {
        method: "POST",
        body: { alert_id: alertId, edr: selected.edr, agent_id: selected.agent_id, confirm_host: confirm, reason, release },
      });
      setMessage({ ok: true, text: r.detail });
      setSelected(null);
      setConfirm("");
      setReason("");
      onDone();
    } catch (e) {
      setMessage({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="isolation-panel stack">
      {!data.enabled && (
        <p className="muted small">
          Isolation de poste désactivée : un administrateur peut l'activer dans Intégrations › Isolation de poste.
        </p>
      )}
      <ul className="plain-list">
        {data.targets.map((t) => (
          <li key={`${t.edr}-${t.agent_id}`} className="row">
            <strong>{t.host || t.agent_id}</strong>
            <span className="muted small">via {EDR_LABEL[t.edr] ?? t.edr}</span>
            {data.enabled && t.configured ? (
              <>
                <button type="button" className="danger-button" onClick={() => { setSelected(t); setRelease(false); }}>
                  Isoler le poste
                </button>
                <button type="button" className="link" onClick={() => { setSelected(t); setRelease(true); }}>
                  Lever l'isolation
                </button>
              </>
            ) : (
              data.enabled && <span className="muted small">accès {EDR_LABEL[t.edr] ?? t.edr} non configuré</span>
            )}
          </li>
        ))}
      </ul>
      {selected && (
        <div className="isolation-confirm stack">
          <p>
            {release ? "Lever l'isolation de " : "Isoler du réseau "}
            <strong>{selected.host}</strong>
            {release
              ? " : le poste retrouve tous ses accès."
              : " : le poste ne pourra plus communiquer qu'avec la console de l'EDR (ses utilisateurs perdent le réseau)."}
          </p>
          <label>
            Motif (tracé dans l'alerte, l'incident et le journal d'audit)
            <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Ex. : rançongiciel suspecté, analyse en cours" />
          </label>
          <label>
            Pour confirmer, saisir le nom du poste : <code>{selected.host}</code>
            <input value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
          </label>
          <div className="row">
            <button type="button" className={release ? "primary" : "danger-button"} disabled={busy || reason.trim().length < 3 ||
              confirm.trim().toLowerCase() !== selected.host.trim().toLowerCase()} onClick={submit}>
              {busy ? "Envoi…" : release ? "Confirmer la levée" : "Confirmer l'isolation"}
            </button>
            <button type="button" className="link" onClick={() => setSelected(null)}>
              Annuler
            </button>
          </div>
        </div>
      )}
      {message && <p className={message.ok ? "text-good" : "text-bad"}>{message.text}</p>}
    </div>
  );
}
