import { ScrollText } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, query } from "../api";
import EventTable from "../components/EventTable";
import { ErrorBanner, PageHeader } from "../components/ui";
import { usePolling } from "../hooks";
import { moduleLabel } from "../labels";
import type { EventRow } from "../types";

const PERIODS: Record<string, number> = { "1h": 1, "24h": 24, "7j": 24 * 7, "30j": 24 * 30, "90j": 24 * 90 };
const FIELDS = ["q", "ip", "user", "host", "module", "category", "outcome", "period", "from", "to"] as const;
const CATEGORIES: Record<string, string> = {
  authentication: "Authentifications",
  intrusion_detection: "Intrusions",
  malware: "Logiciels malveillants",
  network: "Réseau",
  web: "Web",
  iam: "Comptes et droits",
  file: "Fichiers",
  vulnerability: "Vulnérabilités",
  configuration: "Configuration",
};
const hourFr = (iso: string) =>
  new Date(iso).toLocaleString("fr-FR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });

export default function Events() {
  const [params, setParams] = useSearchParams();
  const [form, setForm] = useState<Record<string, string>>(() =>
    Object.fromEntries(FIELDS.map((f) => [f, params.get(f) ?? (f === "period" ? "24h" : "")])),
  );
  const current = Object.fromEntries(FIELDS.map((f) => [f, params.get(f) ?? (f === "period" ? "24h" : "")]));
  const key = FIELDS.map((f) => current[f]).join("|");

  const { data, error, loading } = usePolling(
    () => {
      const hours = PERIODS[current.period] ?? 24;
      // Plage précise (depuis un graphique : une heure donnée), sinon la période choisie
      const since = current.from || new Date(Date.now() - hours * 3600000).toISOString();
      const until = current.to || undefined;
      return api<{ items: EventRow[] }>(
        `/events${query({ q: current.q, ip: current.ip, user: current.user, host: current.host, module: current.module, category: current.category, outcome: current.outcome, since, until, limit: 200 })}`,
      );
    },
    [key],
    0,
  );

  // Menu des sources : seulement les intégrations actives, par ordre alphabétique (plus la source demandée)
  const { data: integrations } = usePolling(
    () => api<{ items: { modules: string[]; enabled: boolean; state: string }[] }>("/integrations"),
    [],
    60000,
  );
  const sources = [
    ...new Set([
      ...(integrations?.items ?? []).filter((i) => i.enabled && i.state !== "planned").flatMap((i) => i.modules),
      ...(current.module ? [current.module] : []),
    ]),
  ].sort((a, b) => moduleLabel(a).localeCompare(moduleLabel(b), "fr"));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const next = new URLSearchParams();
    for (const f of FIELDS) if (form[f]?.trim() && f !== "from" && f !== "to") next.set(f, form[f].trim());
    setParams(next);
  };
  const set = (field: string) => (e: { target: { value: string } }) => setForm({ ...form, [field]: e.target.value });

  return (
    <>
      <PageHeader title="Événements" icon={ScrollText} subtitle="Journaux normalisés de toutes les sources" />
      <form className="filters search-form" onSubmit={submit}>
        <input type="search" placeholder="Texte libre" value={form.q} onChange={set("q")} />
        <input placeholder="Adresse IP" value={form.ip} onChange={set("ip")} className="mono" />
        <input placeholder="Compte" value={form.user} onChange={set("user")} />
        <input placeholder="Poste" value={form.host} onChange={set("host")} />
        <select value={form.module} onChange={set("module")} aria-label="Source">
          <option value="">Toutes sources</option>
          {sources.map((m) => (
            <option key={m} value={m}>
              {moduleLabel(m)}
            </option>
          ))}
        </select>
        <select value={form.category} onChange={set("category")} aria-label="Type">
          <option value="">Tous types</option>
          {Object.entries(CATEGORIES).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <select value={form.outcome} onChange={set("outcome")} aria-label="Résultat">
          <option value="">Tous résultats</option>
          <option value="failure">Échecs</option>
          <option value="success">Succès</option>
        </select>
        <select value={form.period} onChange={set("period")} aria-label="Période">
          {Object.keys(PERIODS).map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <button type="submit" className="primary">
          Rechercher
        </button>
      </form>
      {current.from && (
        <p className="small range-note">
          Plage : du {hourFr(current.from)} au {current.to ? hourFr(current.to) : "maintenant"}.{" "}
          <Link to={`/events?${new URLSearchParams(Object.entries(current).filter(([k, v]) => v && k !== "from" && k !== "to")).toString()}`}>
            Revenir à la période ({current.period})
          </Link>
        </p>
      )}
      <ErrorBanner error={error} />
      {loading ? <p className="muted">Recherche…</p> : <EventTable events={data?.items ?? []} />}
      {data && data.items.length === 200 && <p className="muted small">200 premiers résultats : affinez la recherche.</p>}
    </>
  );
}
