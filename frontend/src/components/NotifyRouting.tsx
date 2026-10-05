import { useEffect, useState } from "react";
import { api } from "../api";
import { SEVERITY_LABEL } from "../labels";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const CHANNELS: [string, string][] = [["email", "E-mail"], ["teams", "Teams"], ["ntfy", "Mobile (ntfy)"]];
const DAYS: [string, string][] = [["1", "lun."], ["2", "mar."], ["3", "mer."], ["4", "jeu."], ["5", "ven."], ["6", "sam."], ["7", "dim."]];

type Values = Record<string, unknown>;
const KEYS = [...SEVERITIES.map((s) => `route_${s}`), "business_hours_only", "business_hours_start", "business_hours_end", "business_days"];

/** Grille de routage : quels canaux pour quelle sévérité, et quelles sévérités attendent les heures ouvrées. */
export default function NotifyRouting() {
  const [values, setValues] = useState<Values | null>(null);
  const [initial, setInitial] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    api<{ values: Values }>("/admin/settings/notify").then((r) => {
      const picked = Object.fromEntries(KEYS.map((k) => [k, r.values[k]]));
      setValues(picked);
      setInitial(JSON.stringify(picked));
    }).catch((e) => setMessage({ ok: false, text: String(e) }));
  }, []);

  if (!values) return <p className="muted">Chargement du routage…</p>;
  const list = (k: string) => ((values[k] as string[]) ?? []).map(String);
  const toggle = (k: string, item: string) => {
    const current = list(k);
    setValues({ ...values, [k]: current.includes(item) ? current.filter((x) => x !== item) : [...current, item] });
  };
  const save = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const r = await api<{ changed: string[] }>("/admin/settings/notify", { method: "PUT", body: values });
      setInitial(JSON.stringify(values));
      setMessage({ ok: true, text: r.changed.length ? "Routage enregistré." : "Aucune modification." });
    } catch (e) {
      setMessage({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="notify-routing">
      <h3>Routage des notifications</h3>
      <p className="muted small">
        Canaux prévenus à la création d'une alerte selon sa sévérité. Une sévérité « aux heures ouvrées » attend
        l'ouverture des bureaux ; les autres sont envoyées aussitôt, nuit et week-end compris. Les alertes faibles non
        notifiées figurent dans le résumé quotidien.
      </p>
      <table className="routing-table">
        <thead>
          <tr>
            <th>Sévérité</th>
            {CHANNELS.map(([, label]) => (
              <th key={label}>{label}</th>
            ))}
            <th>Aux heures ouvrées seulement</th>
          </tr>
        </thead>
        <tbody>
          {SEVERITIES.map((s) => (
            <tr key={s}>
              <td>
                <span className={`badge sev-${s}`}>{SEVERITY_LABEL[s]}</span>
              </td>
              {CHANNELS.map(([c, label]) => (
                <td key={c}>
                  <input type="checkbox" aria-label={`${SEVERITY_LABEL[s]} : ${label}`} checked={list(`route_${s}`).includes(c)}
                    onChange={() => toggle(`route_${s}`, c)} />
                </td>
              ))}
              <td>
                <input type="checkbox" aria-label={`${SEVERITY_LABEL[s]} : heures ouvrées seulement`}
                  checked={list("business_hours_only").includes(s)} onChange={() => toggle("business_hours_only", s)} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="row routing-hours">
        <span>Heures ouvrées :</span>
        {DAYS.map(([d, label]) => (
          <label key={d} className="checkbox">
            <input type="checkbox" checked={list("business_days").includes(d)} onChange={() => toggle("business_days", d)} />
            {label}
          </label>
        ))}
        <label className="inline">
          de
          <input type="number" min={0} max={24} value={Number(values.business_hours_start ?? 8)}
            onChange={(e) => setValues({ ...values, business_hours_start: Number(e.target.value) })} />
        </label>
        <label className="inline">
          à
          <input type="number" min={0} max={24} value={Number(values.business_hours_end ?? 18)}
            onChange={(e) => setValues({ ...values, business_hours_end: Number(e.target.value) })} />
          h
        </label>
      </div>
      <div className="row">
        <button type="button" className="primary" disabled={busy || JSON.stringify(values) === initial} onClick={save}>
          Enregistrer le routage
        </button>
        {message && <span className={message.ok ? "text-good" : "text-bad"}>{message.text}</span>}
      </div>
    </div>
  );
}
