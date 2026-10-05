import { FilterX } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { canEdit, useUser } from "../App";
import { Card, Empty, ErrorBanner, PageHeader } from "../components/ui";
import { usePolling } from "../hooks";
import { formatDate } from "../labels";
import type { Rule, RuleExceptionItem } from "../types";

function inDays(days: number): string {
  const d = new Date(Date.now() + days * 86400000);
  return d.toISOString().slice(0, 10);
}

export default function Exceptions() {
  const user = useUser();
  const list = usePolling(() => api<{ items: RuleExceptionItem[]; fields: string[] }>("/exceptions"), [], 0);
  const rules = usePolling(() => api<{ items: Rule[] }>("/rules"), [], 0);
  const [form, setForm] = useState({ rule_id: "*", field: "source.ip", value: "", reason: "", expires: inDays(30) });
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await api("/exceptions", {
        method: "POST",
        body: { ...form, expires_at: new Date(`${form.expires}T23:59:59`).toISOString() },
      });
      setForm({ ...form, value: "", reason: "" });
      list.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const remove = async (id: number) => {
    if (!window.confirm("Supprimer cette exception ? Les alertes correspondantes pourront à nouveau être créées.")) return;
    await api(`/exceptions/${id}`, { method: "DELETE" }).catch((err) => setError(String(err)));
    list.reload();
  };

  return (
    <>
      <PageHeader title="Exceptions" icon={FilterX} subtitle="Faux positifs connus, avec justification et échéance" />
      <p className="muted">
        Une exception empêche une règle de créer une alerte lorsqu'un champ a une valeur précise (faux positif connu).
        Justification et date d'expiration sont obligatoires.
      </p>
      <ErrorBanner error={list.error} />
      {canEdit(user) && (
        <Card title="Nouvelle exception">
          <form className="exception-form" onSubmit={submit}>
            <label>
              Règle
              <select value={form.rule_id} onChange={(e) => setForm({ ...form, rule_id: e.target.value })}>
                <option value="*">Toutes les règles</option>
                {rules.data?.items.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.id} – {r.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Champ
              <select value={form.field} onChange={(e) => setForm({ ...form, field: e.target.value })}>
                {list.data?.fields.map((f) => (
                  <option key={f}>{f}</option>
                ))}
              </select>
            </label>
            <label>
              Valeur exacte
              <input value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} required />
            </label>
            <label>
              Expire le
              <input type="date" value={form.expires} min={inDays(1)} max={inDays(365)} onChange={(e) => setForm({ ...form, expires: e.target.value })} required />
            </label>
            <label className="span-2">
              Justification
              <input value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} minLength={10} required placeholder="Ex. : scanner de vulnérabilités interne, validé par…" />
            </label>
            {error && <p className="form-error span-2">{error}</p>}
            <button type="submit" className="primary">
              Créer l'exception
            </button>
          </form>
        </Card>
      )}
      {list.data && !list.data.items.length ? (
        <Empty>Aucune exception.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Règle</th>
              <th>Condition</th>
              <th>Justification</th>
              <th>Auteur</th>
              <th>Expiration</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((x) => (
              <tr key={x.id} className={x.active ? "" : "disabled"}>
                <td className="mono">{x.rule_id === "*" ? "toutes" : x.rule_id}</td>
                <td className="mono">
                  {x.field} = {x.value}
                </td>
                <td>{x.reason}</td>
                <td>{x.author}</td>
                <td>{x.active ? formatDate(x.expires_at) : "expirée"}</td>
                <td>
                  {canEdit(user) && (
                    <button className="link danger" onClick={() => remove(x.id)}>
                      Supprimer
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
