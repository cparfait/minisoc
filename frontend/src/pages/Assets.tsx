import { Boxes, Check, FileUp, Globe2, Monitor, Plus, RefreshCw, Server, User as UserIcon } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api, query } from "../api";
import { canEdit, useUser } from "../App";
import ExposureTop from "../components/Exposure";
import { Card, Empty, ErrorBanner, PageHeader } from "../components/ui";
import { usePolling } from "../hooks";
import { formatNumber, timeAgo } from "../labels";

type Criticality = "low" | "normal" | "high" | "vital";
const CRITICALITY: { value: Criticality; label: string }[] = [
  { value: "vital", label: "Vitale" },
  { value: "high", label: "Haute" },
  { value: "normal", label: "Normale" },
  { value: "low", label: "Basse" },
];
// Type d'une machine : « serveur » change l'icône et le libellé partout (une fiche modifiée n'est plus écrasée par les synchronisations)
const HOST_TYPES = [
  { value: "poste", label: "poste" },
  { value: "serveur", label: "serveur" },
];
const SOURCE_LABEL: Record<string, string> = { manual: "saisie", import: "import", ad: "annuaire", ninjaone: "NinjaOne", cyberwatch: "Cyberwatch", alertes: "alertes" };

interface Asset {
  id: number;
  kind: "host" | "account";
  name: string;
  display_name: string;
  criticality: Criticality;
  owner: string;
  service: string;
  description: string;
  asset_type: string;
  source: string;
  reviewed: boolean;
  internet_exposed: boolean;
  updated_at: string | null;
}

interface AssetList {
  items: Asset[];
  by_criticality: Partial<Record<Criticality, number>>;
  to_review: number;
  sync: { at: string; ninjaone: number; cyberwatch?: number; ad_computers: number; ad_accounts: number; alerts: number; created: number; errors: string[] } | null;
}

function EditableText({ value, onSave, disabled, placeholder }: { value: string; onSave: (v: string) => void; disabled: boolean; placeholder: string }) {
  const [text, setText] = useState(value);
  return (
    <input
      className="inline-edit"
      value={text}
      disabled={disabled}
      placeholder={placeholder}
      onChange={(e) => setText(e.target.value)}
      onBlur={() => text !== value && onSave(text.trim())}
      onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
    />
  );
}

export default function Assets() {
  const user = useUser();
  const editable = canEdit(user);
  const [kind, setKind] = useState<"host" | "account">("host");
  const [criticality, setCriticality] = useState("");
  const [toReview, setToReview] = useState(false);
  const [q, setQ] = useState("");
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [importing, setImporting] = useState(false);
  const [csvText, setCsvText] = useState("");
  const { data, error, reload } = usePolling(
    () => api<AssetList>(`/assets${query({ kind, criticality, reviewed: toReview ? "false" : undefined, q })}`),
    [kind, criticality, toReview, q],
    60000,
  );

  const update = async (asset: Asset, changes: Partial<Asset>) => {
    try {
      await api(`/assets/${asset.id}`, { method: "PUT", body: changes });
      setMessage({ ok: true, text: `${asset.display_name} : enregistré.` });
      reload();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    }
  };
  const sync = async () => {
    const r = await api<{ detail: string }>("/assets/sync", { method: "POST" });
    setMessage({ ok: true, text: r.detail });
    setTimeout(reload, 15000);
  };
  const add = async () => {
    const name = window.prompt(kind === "host" ? "Nom de la machine :" : "Identifiant du compte :");
    if (!name) return;
    try {
      await api("/assets", { method: "POST", body: { kind, name } });
      reload();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    }
  };
  const importCsv = async () => {
    try {
      const r = await api<{ rows: number; created: number; updated: number }>("/assets/import", { method: "POST", body: { text: csvText } });
      setMessage({ ok: true, text: `Import : ${r.rows} ligne(s), ${r.created} créée(s), ${r.updated} mise(s) à jour.` });
      setImporting(false);
      setCsvText("");
      reload();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    }
  };

  const counts = data?.by_criticality ?? {};
  return (
    <>
      <PageHeader title="Inventaire" icon={Boxes} subtitle="Machines et comptes : criticité, propriétaire, service">
        {editable && (
          <div className="row">
            <button type="button" className="ghost small" onClick={sync}><RefreshCw size={14} /> Synchroniser</button>
            <button type="button" className="ghost small" onClick={() => setImporting(!importing)}><FileUp size={14} /> Importer (CSV)</button>
            <button type="button" className="ghost small" onClick={add}><Plus size={14} /> Ajouter</button>
          </div>
        )}
      </PageHeader>
      <p className="muted">
        La criticité entre dans la priorité des alertes (vitale +20, haute +10, basse −10) ; le propriétaire et le
        service s'affichent avec les machines touchées. Une fiche modifiée ici est « classée » : les synchronisations
        (NinjaOne, Cyberwatch, annuaire, alertes) ne la modifient plus.
      </p>
      <div className="kpi-row assets-kpis">
        {CRITICALITY.map((c) => (
          <button key={c.value} type="button" className={`kpi-mini crit-${c.value} ${criticality === c.value ? "active" : ""}`}
            onClick={() => setCriticality(criticality === c.value ? "" : c.value)}>
            <strong>{formatNumber(counts[c.value] ?? 0)}</strong>
            <span>{c.label}</span>
          </button>
        ))}
        <button type="button" className={`kpi-mini ${toReview ? "active" : ""}`} onClick={() => setToReview(!toReview)}>
          <strong>{formatNumber(data?.to_review ?? 0)}</strong>
          <span>à classer</span>
        </button>
      </div>
      {data?.sync && (
        <p className="muted small">
          Dernière synchronisation {timeAgo(data.sync.at)} : NinjaOne {data.sync.ninjaone}, Cyberwatch {data.sync.cyberwatch ?? 0}, annuaire {data.sync.ad_computers} machine(s) et{" "}
          {data.sync.ad_accounts} compte(s) sensible(s), alertes {data.sync.alerts} ; {data.sync.created} nouvelle(s) fiche(s).
          {data.sync.errors.length > 0 && <span className="text-bad"> {data.sync.errors.join(" ; ")}</span>}
        </p>
      )}
      {message && <p className={message.ok ? "text-good" : "text-bad"}>{message.text}</p>}
      <ErrorBanner error={error} />
      <ExposureTop limit={10} collapsible />

      {importing && (
        <Card title="Importer un inventaire (CSV)">
          <p className="muted small">
            Une ligne par machine ou compte, séparateur <code>;</code> : <code>nom;type;criticité;propriétaire;service;description</code>.
            Type : machine ou compte ; criticité : basse, normale, haute, vitale. L'en-tête est facultatif. Exemple :
          </p>
          <pre className="small">{"nom;type;criticité;propriétaire;service\nPC-00742;machine;vitale;Directeur général des services;Direction générale\nSRV-PAIE;machine;vitale;;Ressources humaines\nadm.dupont;compte;haute;J. Dupont;DSI"}</pre>
          <textarea rows={8} className="mono" value={csvText} onChange={(e) => setCsvText(e.target.value)} placeholder="Coller le CSV ici" />
          <div className="row">
            <button type="button" className="primary" disabled={!csvText.trim()} onClick={importCsv}>Importer</button>
            <label className="ghost small file-pick">
              ou choisir un fichier
              <input type="file" accept=".csv,.txt" onChange={async (e) => { const f = e.target.files?.[0]; if (f) setCsvText(await f.text()); }} />
            </label>
          </div>
        </Card>
      )}

      <div className="filters">
        <div className="segmented" role="group" aria-label="Type">
          <button className={kind === "host" ? "active" : ""} onClick={() => setKind("host")}><Monitor size={14} /> Machines</button>
          <button className={kind === "account" ? "active" : ""} onClick={() => setKind("account")}><UserIcon size={14} /> Comptes</button>
        </div>
        <input type="search" placeholder="Rechercher (nom, propriétaire, service…)" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>

      {data && data.items.length === 0 ? (
        <Empty icon={Boxes}>
          Aucune fiche. {editable && "« Synchroniser » importe les machines de NinjaOne, de Cyberwatch et de l'annuaire, et celles citées par les alertes."}
        </Empty>
      ) : (
        <div className="table-scroll">
          <table className="assets-table">
            <thead>
              <tr>
                <th>{kind === "host" ? "Machine" : "Compte"}</th>
                <th>Criticité</th>
                {kind === "host" && <th title="Service publié sur Internet (site web, messagerie, VPN, accès distant…)">Internet</th>}
                <th>Propriétaire</th>
                <th>Service</th>
                <th>Description</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {data?.items.map((a) => (
                <tr key={a.id} className={a.reviewed ? "" : "to-review"}>
                  <td className="nowrap">
                    <span className="impacted-name">
                      {a.kind === "account" ? <UserIcon size={14} /> : a.asset_type === "serveur" ? <Server size={14} /> : <Monitor size={14} />}
                      <Link to={`/assets/${a.kind}/${encodeURIComponent(a.display_name)}`} className="asset-link">
                        <strong className="mono">{a.display_name}</strong>
                      </Link>
                      {a.reviewed && <span title="Classée par la DSI"><Check size={13} className="text-good" /></span>}
                    </span>
                    {a.kind === "host" ? (
                      <select className="type-select" value={a.asset_type} disabled={!editable} aria-label="Type de machine"
                        onChange={(e) => update(a, { asset_type: e.target.value })}>
                        {!HOST_TYPES.some((t) => t.value === a.asset_type) && <option value={a.asset_type}>{a.asset_type || "type ?"}</option>}
                        {HOST_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                      </select>
                    ) : (
                      a.asset_type && <div className="muted small">{a.asset_type}</div>
                    )}
                  </td>
                  <td>
                    <select className={`crit-select crit-${a.criticality}`} value={a.criticality} disabled={!editable}
                      onChange={(e) => update(a, { criticality: e.target.value as Criticality })}>
                      {CRITICALITY.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
                    </select>
                  </td>
                  {kind === "host" && (
                    <td>
                      <button
                        type="button"
                        className={`exposed-toggle ${a.internet_exposed ? "on" : ""}`}
                        disabled={!editable}
                        aria-pressed={a.internet_exposed}
                        title={a.internet_exposed ? "Exposée à Internet : cliquer pour retirer" : "Non exposée : cliquer si un service est publié sur Internet"}
                        onClick={() => update(a, { internet_exposed: !a.internet_exposed })}
                      >
                        <Globe2 size={13} /> {a.internet_exposed ? "Exposée" : "Non"}
                      </button>
                    </td>
                  )}
                  <td><EditableText key={`o${a.id}${a.owner}`} value={a.owner} disabled={!editable} placeholder="—" onSave={(v) => update(a, { owner: v })} /></td>
                  <td><EditableText key={`s${a.id}${a.service}`} value={a.service} disabled={!editable} placeholder="—" onSave={(v) => update(a, { service: v })} /></td>
                  <td className="small muted assets-desc" title={a.description}>{a.description || "—"}</td>
                  <td className="small">{SOURCE_LABEL[a.source] ?? a.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
