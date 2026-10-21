import { LayoutTemplate, RefreshCw } from "lucide-react";
import { Fragment, useState, type FormEvent } from "react";
import { api } from "../api";
import { canEdit, useUser } from "../App";
import { usePolling } from "../hooks";
import { formatDate, timeAgo } from "../labels";
import { Card, Empty, ErrorBanner } from "./ui";

interface Vuln {
  id: string;
  title: string;
  fixed_in: string;
  type: string;
  cves: string[];
  score: number | null;
}
interface Component {
  kind: "core" | "plugin" | "theme";
  slug: string;
  name: string;
  installed: string;
  latest: string;
  update: "" | "correctif" | "version";
  active: boolean;
  vulns: Vuln[] | null;
}
interface Site {
  url: string;
  name: string;
  mode: "api" | "public" | null;
  scanned_at: string | null;
  error: string;
  vulns_checked: boolean;
  core: string;
  core_latest: string;
  updates: number;
  plugins: number;
  themes: number;
  vulnerable: number;
  vulns: number;
  components: Component[];
}
interface Overview {
  enabled: boolean;
  declared: number;
  vulns_enabled: boolean;
  status: { state?: "running" | "ok" | "error"; started?: string; finished?: string; errors?: string[]; quota_reached?: boolean };
  sites: Site[];
}
interface DeclaredSite {
  url: string;
  user: string;
  password_set: boolean;
}

const KIND: Record<Component["kind"], string> = { core: "WordPress", plugin: "Extension", theme: "Thème" };

function statusLine(o: Overview): { text: string; bad: boolean } {
  const s = o.status;
  if (s.state === "running") return { text: `Inventaire en cours (démarré ${timeAgo(s.started)}).`, bad: false };
  if (!s.finished) return { text: "Premier inventaire dans la minute qui suit l'activation, puis chaque jour.", bad: false };
  const failed = s.errors?.length ? ` En échec : ${s.errors.join(" ; ")}.` : "";
  const quota = s.quota_reached ? " Quota WPScan du jour atteint : la vérification des failles continue demain." : "";
  return { text: `Dernier inventaire ${timeAgo(s.finished)}.${failed}${quota}`, bad: Boolean(s.errors?.length) };
}

function ScanButton({ onDone }: { onDone: (text: string, ok: boolean) => void }) {
  const [busy, setBusy] = useState(false);
  return (
    <button type="button" disabled={busy} onClick={async () => {
      setBusy(true);
      try {
        await api("/wordpress/scan", { method: "POST" });
        onDone("Inventaire demandé : il démarre dans la minute (quelques secondes par site).", true);
      } catch (err) {
        onDone(err instanceof Error ? err.message : String(err), false);
      } finally {
        setBusy(false);
      }
    }}>
      <RefreshCw size={14} /> Analyser maintenant
    </button>
  );
}

function VulnList({ vulns }: { vulns: Vuln[] | null }) {
  if (vulns === null) return <span className="muted">non vérifiées</span>;
  if (!vulns.length) return <span className="muted">aucune connue</span>;
  return (
    <ul className="plain-list">
      {vulns.map((v) => (
        <li key={v.id} className="small">
          <span className="text-bad">{v.title}</span>
          {v.cves.length > 0 && <span className="muted"> · {v.cves.join(", ")}</span>}
          {v.score !== null && <span className="muted"> · CVSS {v.score}</span>}
          <span className={v.fixed_in ? "text-good" : "muted"}> · {v.fixed_in ? `corrigée en ${v.fixed_in}` : "pas encore de correctif"}</span>
        </li>
      ))}
    </ul>
  );
}

function SiteDetail({ site }: { site: Site }) {
  // À traiter d'abord : failles, puis mises à jour, puis le reste
  const rank = (c: Component) => (c.vulns?.length ? 0 : c.update ? 1 : 2);
  const rows = [...site.components].sort((a, b) => rank(a) - rank(b) || (a.kind === "core" ? -1 : 0) || a.name.localeCompare(b.name));
  return (
    <table className="wp-components">
      <thead>
        <tr><th>Composant</th><th>Installée</th><th>Dernière</th><th>Failles connues</th></tr>
      </thead>
      <tbody>
        {rows.map((c) => (
          <tr key={`${c.kind}-${c.slug}`} className={c.active ? "" : "muted"}>
            <td>
              <span className="role-tag">{KIND[c.kind]}</span>
              {c.kind === "core" ? "WordPress" : c.name || c.slug}
              {!c.active && <span className="muted small"> (désactivé{c.kind === "theme" ? "" : "e"})</span>}
            </td>
            <td className="mono small">{c.installed || <span className="muted">{c.kind === "core" ? "masquée" : "inconnue"}</span>}</td>
            <td className="mono small">
              {c.latest ? (
                c.update ? <strong className={c.update === "version" ? "text-warn" : "text-bad"}>{c.latest} ({c.update === "version" ? "nouvelle version" : "correctif"})</strong> : <span className="text-good">à jour</span>
              ) : (
                <span className="muted" title="Absent de l'annuaire wordpress.org (extension payante ou sur mesure)">hors wordpress.org</span>
              )}
            </td>
            <td><VulnList vulns={c.vulns} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Page Vulnérabilités : sites WordPress, mises à jour à faire et failles connues. */
export function WordPressSites() {
  const user = useUser();
  const { data, error, reload } = usePolling(() => api<Overview>("/wordpress/overview"), [], 60000);
  const [open, setOpen] = useState<string | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  if (!data) return <ErrorBanner error={error} />;
  if (!data.enabled) return null;
  const line = statusLine(data);
  return (
    <Card title="Sites WordPress" icon={LayoutTemplate}>
      <div className="filters">
        <span className={`small ${line.bad ? "text-bad" : "muted"}`}>{line.text}</span>
        <span className="spacer" />
        {canEdit(user) && <ScanButton onDone={(text, ok) => { setMessage({ ok, text }); reload(); }} />}
      </div>
      {message && <p className={`small ${message.ok ? "text-good" : "text-bad"}`}>{message.text}</p>}
      {data.sites.length ? (
        <table>
          <thead>
            <tr>
              <th>Site</th>
              <th>Inventaire</th>
              <th>WordPress</th>
              <th className="num">Extensions</th>
              <th className="num">Thèmes</th>
              <th className="num">Mises à jour</th>
              <th className="num">Composants vulnérables</th>
            </tr>
          </thead>
          <tbody>
            {data.sites.map((s) => (
              <Fragment key={s.url}>
                <tr className="clickable" onClick={() => setOpen(open === s.url ? null : s.url)} aria-expanded={open === s.url}>
                  <td>
                    <a href={s.url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>{s.name}</a>
                    {s.mode === "public" && <span className="role-tag" title="Sans mot de passe d'application : liste issue de la partie publique du site, parfois incomplète">public</span>}
                    {s.error && <div className="text-bad small">{s.error}</div>}
                  </td>
                  <td className="small" title={formatDate(s.scanned_at)}>{s.scanned_at ? timeAgo(s.scanned_at) : "en attente"}</td>
                  <td className="mono small">
                    {s.core || <span className="muted">masquée</span>}
                    {s.core && s.core_latest && s.core !== s.core_latest && <span className="text-warn"> → {s.core_latest}</span>}
                  </td>
                  <td className="num">{s.plugins}</td>
                  <td className="num">{s.themes}</td>
                  <td className={`num ${s.updates ? "text-warn" : ""}`}>{s.updates || "—"}</td>
                  <td className={`num ${s.vulnerable ? "text-bad" : ""}`}>
                    {s.vulns_checked ? s.vulnerable || "—" : <span className="muted" title="Jeton WPScan non renseigné">?</span>}
                  </td>
                </tr>
                {open === s.url && (
                  <tr className="wp-detail">
                    <td colSpan={7}>
                      {s.components.length ? <SiteDetail site={s} /> : <Empty>Pas encore d'inventaire pour ce site.</Empty>}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      ) : (
        <Empty>Aucun site déclaré (Intégrations › WordPress › Configuration).</Empty>
      )}
      {!data.vulns_enabled && data.sites.length > 0 && (
        <p className="muted small">
          Failles connues non vérifiées : renseigner un jeton WPScan (gratuit) dans Intégrations › WordPress pour les
          afficher et être alerté.
        </p>
      )}
    </Card>
  );
}

/** Fiche de l'intégration (onglet Configuration) : sites déclarés et identifiants (mots de passe d'application). */
export function WordPressAdmin() {
  const sites = usePolling(() => api<{ items: DeclaredSite[] }>("/admin/wordpress/sites"), [], 0);
  const [form, setForm] = useState({ url: "", user: "", password: "" });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await api("/admin/wordpress/sites", { method: "PUT", body: form });
      setMessage({ ok: true, text: `${form.url} enregistré. « Analyser maintenant » pour un premier inventaire.` });
      setForm({ url: "", user: "", password: "" });
      sites.reload();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };
  const remove = async (s: DeclaredSite) => {
    if (!window.confirm(`Retirer ${s.url} ? Son inventaire est effacé ; le mot de passe d'application reste à révoquer sur le site.`)) return;
    try {
      await api(`/admin/wordpress/sites?url=${encodeURIComponent(s.url)}`, { method: "DELETE" });
      sites.reload();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    }
  };

  return (
    <div className="integration-admin">
      <h3>Sites WordPress</h3>
      <p className="muted small">
        Identifiant et <strong>mot de passe d'application</strong> d'un compte administrateur du site (Utilisateurs ›
        Profil › Mots de passe d'application) : liste exacte des extensions et thèmes. Sans identifiant, seule la partie
        publique du site est inventoriée. Les mots de passe sont chiffrés et jamais réaffichés.
      </p>
      <form className="settings-form" onSubmit={save}>
        <div className="settings-field">
          <label>
            Adresse du site *
            <input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder="https://www.mairie.fr" required maxLength={300} />
          </label>
        </div>
        <div className="settings-field">
          <label>
            Identifiant
            <input value={form.user} onChange={(e) => setForm({ ...form, user: e.target.value })} placeholder="minisoc" maxLength={120} autoComplete="off" />
          </label>
        </div>
        <div className="settings-field">
          <label>
            Mot de passe d'application
            <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} placeholder="xxxx xxxx xxxx xxxx xxxx xxxx" maxLength={200} autoComplete="new-password" />
          </label>
          <small className="muted">Site déjà déclaré : laisser vide pour garder le mot de passe enregistré.</small>
        </div>
        <div className="settings-actions">
          <button type="submit" className="primary" disabled={busy || !form.url.trim()}>Enregistrer le site</button>
        </div>
      </form>
      {message && <p className={message.ok ? "text-good" : "text-bad"}>{message.text}</p>}
      <ErrorBanner error={sites.error} />
      {sites.data && sites.data.items.length > 0 && (
        <table>
          <thead>
            <tr><th>Site</th><th>Accès</th><th /></tr>
          </thead>
          <tbody>
            {sites.data.items.map((s) => (
              <tr key={s.url}>
                <td>{s.url}</td>
                <td className="small">{s.user ? `${s.user}${s.password_set ? " · mot de passe d'application enregistré" : " · mot de passe manquant"}` : "partie publique seulement"}</td>
                <td>
                  <button type="button" className="link" onClick={() => setForm({ url: s.url, user: s.user, password: "" })}>Modifier</button>{" "}
                  <button type="button" className="link danger" onClick={() => remove(s)}>Retirer</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
