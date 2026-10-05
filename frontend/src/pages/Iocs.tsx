import { Crosshair, Link2, Play, RefreshCw, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api, query } from "../api";
import { canEdit, useUser } from "../App";
import { Card, Empty, ErrorBanner, PageHeader } from "../components/ui";
import { usePolling } from "../hooks";
import { formatDate, formatNumber, timeAgo } from "../labels";

const TYPE_LABEL: Record<string, string> = { ip: "IP / réseau", domain: "Domaine", hash: "Empreinte", url: "URL" };

interface IocRow {
  id: number;
  type: string;
  value: string;
  source: string;
  description: string;
  author: string;
  hits: number;
  last_hit: string | null;
  hunted_at: string | null;
  expires_at: string | null;
  created_at: string | null;
}

interface IocList {
  items: IocRow[];
  by_type: Record<string, number>;
  pending: number;
  status: { at: string; iocs: number; new: number; alerts: number; error?: string } | null;
}

interface Feed {
  id: number;
  name: string;
  url: string;
  type: string;
  enabled: boolean;
  count: number;
  error: string;
  fetched_at: string | null;
}

/** Recherche des événements correspondant à l'IOC (page Recherche, 1 an). */
function searchLink(i: IocRow): string {
  const q = i.type === "ip" ? `ip=${i.value}` : `"${i.value}"`;
  return `/search?${new URLSearchParams({ q, period: "365d" })}`;
}

function Feeds({ admin }: { admin: boolean }) {
  const { data, error, reload } = usePolling(() => api<{ items: Feed[] }>("/iocs/feeds"), [], 60000);
  const [form, setForm] = useState({ name: "", url: "", type: "auto" });
  const [message, setMessage] = useState<string | null>(null);
  const act = async (fn: () => Promise<unknown>) => {
    setMessage(null);
    try {
      await fn();
      reload();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : String(err));
    }
  };
  return (
    <Card title="Listes externes" icon={Link2}>
      <p className="muted small">
        Listes publiques d'indicateurs (une valeur par ligne), relues chaque jour ; par exemple les listes d'abuse.ch
        (Feodo Tracker, URLhaus) ou celles d'un CERT. Les alertes issues d'une liste sont de sévérité moyenne.
      </p>
      <ErrorBanner error={error ?? message} />
      {data && data.items.length > 0 && (
        <table className="small">
          <thead>
            <tr><th>Nom</th><th>Type</th><th className="num">IOC</th><th>Dernière lecture</th><th /></tr>
          </thead>
          <tbody>
            {data.items.map((f) => (
              <tr key={f.id} className={f.enabled ? "" : "disabled"}>
                <td>
                  <strong>{f.name}</strong>
                  <div className="muted mono small feed-url">{f.url}</div>
                  {f.error && <div className="text-bad small">{f.error}</div>}
                </td>
                <td>{f.type === "auto" ? "auto" : TYPE_LABEL[f.type]}</td>
                <td className="num">{formatNumber(f.count)}</td>
                <td>{f.fetched_at ? timeAgo(f.fetched_at) : "à venir"}</td>
                <td className="nowrap">
                  {admin && (
                    <>
                      <label className="switch small" title={f.enabled ? "Désactiver" : "Activer"}>
                        <input type="checkbox" checked={f.enabled} onChange={(e) => act(() => api(`/iocs/feeds/${f.id}`, { method: "PATCH", body: { enabled: e.target.checked } }))} />
                        <span />
                      </label>
                      <button type="button" className="icon-button" title="Relire maintenant" onClick={() => act(() => api(`/iocs/feeds/${f.id}/fetch`, { method: "POST" }))}><RefreshCw size={14} /></button>
                      <button type="button" className="icon-button" title="Supprimer la liste et ses IOC"
                        onClick={() => window.confirm(`Supprimer « ${f.name} » et ses ${f.count} IOC ?`) && act(() => api(`/iocs/feeds/${f.id}`, { method: "DELETE" }))}><Trash2 size={14} /></button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {admin && (
        <form className="row feed-form" onSubmit={(e) => { e.preventDefault(); act(() => api("/iocs/feeds", { method: "POST", body: form })).then(() => setForm({ name: "", url: "", type: "auto" })); }}>
          <input placeholder="Nom (ex. Feodo Tracker)" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          <input className="grow mono" placeholder="https://feodotracker.abuse.ch/downloads/ipblocklist.txt" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} required />
          <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
            <option value="auto">type automatique</option>
            {Object.entries(TYPE_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
          <button type="submit">Ajouter la liste</button>
        </form>
      )}
    </Card>
  );
}

export default function Iocs() {
  const user = useUser();
  const editable = canEdit(user);
  const [type, setType] = useState("");
  const [q, setQ] = useState("");
  const [hitsOnly, setHitsOnly] = useState(false);
  const [form, setForm] = useState({ text: "", type: "auto", description: "", source: "", expires_days: "" });
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const { data, error, reload } = usePolling(() => api<IocList>(`/iocs${query({ type, q, hits: hitsOnly ? "true" : undefined })}`), [type, q, hitsOnly], 15000);

  const add = async () => {
    setMessage(null);
    try {
      const r = await api<{ added: number; duplicates: number; rejected: string[]; rejected_count: number }>("/iocs", {
        method: "POST",
        body: { ...form, source: form.source || "manuel", expires_days: form.expires_days ? Number(form.expires_days) : null },
      });
      setMessage({
        ok: true,
        text: `${r.added} IOC ajouté(s)${r.duplicates ? `, ${r.duplicates} déjà présent(s)` : ""}${r.rejected_count ? `, ${r.rejected_count} refusé(s) : ${r.rejected.slice(0, 3).join(" ; ")}` : ""}. Chasse sur tout l'historique lancée.`,
      });
      setForm({ ...form, text: "" });
      reload();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    }
  };
  const hunt = async () => {
    const r = await api<{ detail: string }>("/iocs/hunt", { method: "POST" });
    setMessage({ ok: true, text: r.detail });
    setTimeout(reload, 8000);
  };

  return (
    <>
      <PageHeader title="Indicateurs de compromission" icon={Crosshair} subtitle="Chasse dans tout l'historique des journaux">
        {editable && <button type="button" className="ghost small" onClick={hunt}><Play size={14} /> Chasser maintenant</button>}
      </PageHeader>
      <p className="muted">
        Chaque nouvel indicateur est recherché dans <strong>tout l'historique conservé</strong>, puis tous les indicateurs
        dans les nouveaux journaux, toutes les 10 minutes. Une correspondance crée une alerte (règle UC-42), notifiée même
        si l'événement est ancien : une découverte rétroactive peut révéler une compromission en cours.
      </p>
      {data?.status && (
        <p className="muted small">
          Dernière chasse {timeAgo(data.status.at)} : {formatNumber(data.status.iocs)} indicateur(s), dont {data.status.new} nouveau(x) chassé(s) sur
          l'historique ; {data.status.alerts} alerte(s) créée(s).
          {data.pending > 0 && <> {data.pending} en attente de chasse.</>}
          {data.status.error && <span className="text-bad"> {data.status.error}</span>}
        </p>
      )}
      {message && <p className={message.ok ? "text-good" : "text-bad"}>{message.text}</p>}
      <ErrorBanner error={error} />

      {editable && (
        <Card title="Ajouter des indicateurs">
          <p className="muted small">
            Une valeur par ligne (ou séparées par des virgules) : adresses IP ou réseaux (/16 au plus large), domaines, empreintes
            MD5/SHA-1/SHA-256, URL. Les formes neutralisées des bulletins (<code>hxxp</code>, <code>[.]</code>) sont acceptées ;
            <code>#</code> commence un commentaire.
          </p>
          <textarea rows={5} className="mono" value={form.text} onChange={(e) => setForm({ ...form, text: e.target.value })}
            placeholder={"203.0.113.45\nevil-domain[.]example\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"} />
          <div className="row ioc-form">
            <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })} aria-label="Type">
              <option value="auto">Type automatique</option>
              {Object.entries(TYPE_LABEL).map(([v, l]) => <option key={v} value={v}>{l} seulement</option>)}
            </select>
            <input placeholder="Source (ex. CERTFR-2026-ALE-012)" value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} />
            <input className="grow" placeholder="Description / contexte" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            <input type="number" min={1} placeholder="Validité (jours)" value={form.expires_days} onChange={(e) => setForm({ ...form, expires_days: e.target.value })} />
            <button type="button" className="primary" disabled={!form.text.trim()} onClick={add}>Ajouter et chasser</button>
          </div>
        </Card>
      )}

      <div className="filters">
        <div className="segmented" role="group" aria-label="Type">
          <button className={type === "" ? "active" : ""} onClick={() => setType("")}>Tous</button>
          {Object.entries(TYPE_LABEL).map(([v, l]) => (
            <button key={v} className={type === v ? "active" : ""} onClick={() => setType(v)}>
              {l}<span className="count">{formatNumber(data?.by_type[v] ?? 0)}</span>
            </button>
          ))}
        </div>
        <label className="checkbox"><input type="checkbox" checked={hitsOnly} onChange={(e) => setHitsOnly(e.target.checked)} /> Avec correspondances</label>
        <input type="search" placeholder="Rechercher une valeur ou une source" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>

      {data && data.items.length === 0 ? (
        <Empty icon={Crosshair}>Aucun indicateur{hitsOnly ? " avec correspondance" : ""}.</Empty>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr><th>Type</th><th>Valeur</th><th>Source</th><th className="num">Correspondances</th><th>Dernière</th><th>Chassé</th><th /></tr>
            </thead>
            <tbody>
              {data?.items.map((i) => (
                <tr key={i.id} className={i.hits ? "ioc-hit" : ""}>
                  <td className="small">{TYPE_LABEL[i.type] ?? i.type}</td>
                  <td className="mono ioc-value" title={i.description}>
                    {i.value}
                    {i.description && <div className="muted small">{i.description}</div>}
                  </td>
                  <td className="small">{i.source}</td>
                  <td className="num">{i.hits ? <Link to={searchLink(i)}><strong className="text-bad">{formatNumber(i.hits)}</strong></Link> : "0"}</td>
                  <td className="small nowrap">{i.last_hit ? formatDate(i.last_hit) : "—"}</td>
                  <td className="small nowrap">{i.hunted_at ? timeAgo(i.hunted_at) : <span className="muted">en attente</span>}</td>
                  <td>
                    {editable && (
                      <button type="button" className="icon-button" title="Supprimer"
                        onClick={() => window.confirm(`Supprimer ${i.value} ?`) && api(`/iocs/${i.id}`, { method: "DELETE" }).then(reload)}><Trash2 size={14} /></button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Feeds admin={user?.role === "admin"} />
    </>
  );
}
