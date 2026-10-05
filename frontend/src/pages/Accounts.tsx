import { UserCog } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useUser } from "../App";
import { Card, Empty, ErrorBanner, PageHeader } from "../components/ui";
import { usePolling } from "../hooks";
import { formatDate, formatNumber, timeAgo } from "../labels";

interface Origin {
  host: string;
  ip: string;
  service: string;
  failures: number;
  last: string | null;
}
interface Lockout {
  user: string;
  roles: string;
  lockouts: number;
  locked_at: string;
  caller: string;
  still_locked: boolean;
  unlocked_at: string | null;
  unlocked_by: string;
  last_logon: string | null;
  origins: Origin[];
}
interface Account {
  name: string;
  display_name: string;
  description: string;
  roles: string[];
  source: "ad" | "motif";
  disabled: boolean;
  password_never_expires: boolean;
  unconstrained_delegation: boolean;
  spn_count: number;
  password_set: string | null;
  ad_last_logon: string | null;
  logons_7d: number;
  failures_7d: number;
  lockouts_7d: number;
  hosts_7d: number;
  last_logon: string | null;
  last_host: string;
  last_service: string;
}
interface Overview {
  ad_configured: boolean;
  ad_sync: boolean;
  sync: { at: string; admin: number; service: number; error: string } | null;
  patterns: { admin: string[]; service: string[] };
  lockouts: Lockout[];
  accounts: Account[];
}

const ROLE_LABEL: Record<string, string> = { admin: "Administrateur", service: "Compte de service" };
const SERVICE_LABEL: Record<string, string> = {
  interactive: "au clavier",
  rdp: "bureau à distance",
  network: "réseau",
  unlock: "déverrouillage",
  cached: "hors ligne",
  network_cleartext: "réseau (en clair)",
  kerberos: "Kerberos",
  ntlm: "NTLM",
};
const YEAR = 365 * 86400000;

const roleTags = (roles: string[] | string) =>
  (Array.isArray(roles) ? roles : roles.split(",")).filter(Boolean).map((r) => (
    <span key={r} className={`role-tag role-${r}`}>
      {ROLE_LABEL[r] ?? r}
    </span>
  ));

function Warnings({ a }: { a: Account }) {
  const items: string[] = [];
  if (a.roles.includes("service") && (a.last_service === "interactive" || a.last_service === "rdp"))
    items.push("session interactive récente");
  if (a.password_never_expires) items.push("mot de passe sans expiration");
  if (a.password_set && Date.now() - new Date(a.password_set).getTime() > YEAR) items.push("mot de passe de plus d'un an");
  if (a.unconstrained_delegation) items.push("délégation non contrainte");
  if (a.disabled && a.logons_7d > 0) items.push("désactivé mais utilisé");
  if (!items.length) return <span className="muted">—</span>;
  return (
    <ul className="warn-list">
      {items.map((i) => (
        <li key={i}>{i}</li>
      ))}
    </ul>
  );
}

export default function Accounts() {
  const user = useUser();
  const { data, error, reload } = usePolling(() => api<Overview>("/accounts"), [], 30000);
  const [showUnlocked, setShowUnlocked] = useState(false);
  const [role, setRole] = useState("");
  const [search, setSearch] = useState("");
  const [syncing, setSyncing] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);

  const lockouts = useMemo(
    () => (data?.lockouts ?? []).filter((l) => showUnlocked || l.still_locked),
    [data, showUnlocked],
  );
  const accounts = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (data?.accounts ?? [])
      .filter((a) => !role || a.roles.includes(role))
      .filter((a) => !needle || `${a.name} ${a.display_name} ${a.description}`.toLowerCase().includes(needle));
  }, [data, role, search]);

  const sync = async () => {
    setSyncing(true);
    setSyncError(null);
    try {
      await api("/admin/accounts/sync", { method: "POST" });
      await reload();
    } catch (e) {
      setSyncError(e instanceof Error ? e.message : String(e));
    } finally {
      setSyncing(false);
    }
  };

  const stillLocked = (data?.lockouts ?? []).filter((l) => l.still_locked).length;
  const count = (r: string) => (data?.accounts ?? []).filter((a) => a.roles.includes(r)).length;

  return (
    <>
      <PageHeader title="Comptes AD" icon={UserCog} subtitle="Comptes verrouillés, administrateurs et comptes de service" />
      <p className="muted">
        Comptes verrouillés et origine des échecs, surveillance des comptes administrateurs et des comptes de service
        (règles UC-23 à UC-31). Sources : journaux des contrôleurs de domaine (NXLog) et annuaire lu en LDAPS.
      </p>
      <ErrorBanner error={error ?? syncError} />

      <Card title={`Comptes verrouillés (24 h) — ${stillLocked} encore verrouillé(s)`}>
        <div className="filters">
          <label className="checkbox">
            <input type="checkbox" checked={showUnlocked} onChange={(e) => setShowUnlocked(e.target.checked)} />
            Afficher aussi les comptes déverrouillés depuis
          </label>
        </div>
        {data && !lockouts.length ? (
          <Empty>{showUnlocked ? "Aucun verrouillage depuis 24 h." : "Aucun compte verrouillé actuellement."}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Compte</th>
                <th>Verrouillé</th>
                <th>Poste à l'origine</th>
                <th>Échecs (24 h) par provenance</th>
                <th>État</th>
              </tr>
            </thead>
            <tbody>
              {lockouts.map((l) => (
                <tr key={l.user}>
                  <td>
                    <Link to={`/events?user=${encodeURIComponent(l.user)}`}>{l.user}</Link> {roleTags(l.roles)}
                  </td>
                  <td className="nowrap" title={formatDate(l.locked_at)}>
                    {timeAgo(l.locked_at)}
                    {l.lockouts > 1 && <div className="text-bad small">{l.lockouts} verrouillages en 24 h</div>}
                  </td>
                  <td className="mono">
                    {l.caller ? <Link to={`/events?host=${encodeURIComponent(l.caller)}`}>{l.caller}</Link> : "—"}
                  </td>
                  <td className="small">
                    {l.origins.length ? (
                      <ul className="origin-list">
                        {l.origins.map((o, i) => (
                          <li key={i}>
                            <strong>{formatNumber(o.failures)}</strong> depuis{" "}
                            <span className="mono">{[o.host, o.ip].filter(Boolean).join(" / ") || "?"}</span>
                            {o.service && <span className="muted"> ({SERVICE_LABEL[o.service] ?? o.service})</span>}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <span className="muted">aucun échec transmis</span>
                    )}
                  </td>
                  <td>
                    {l.still_locked ? (
                      <span className="state-pill state-silent">Verrouillé</span>
                    ) : (
                      <span className="state-pill state-active" title={formatDate(l.unlocked_at ?? l.last_logon)}>
                        {l.unlocked_at ? `Déverrouillé${l.unlocked_by ? ` par ${l.unlocked_by}` : ""}` : "Reconnecté"}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted small">
          Le poste à l'origine est celui qui a envoyé les mauvais mots de passe (téléphone, session ouverte ailleurs,
          lecteur réseau ou tâche planifiée avec un ancien mot de passe…). Un déverrouillage automatique par la durée de
          verrouillage du domaine n'est pas journalisé par Windows : le compte apparaît verrouillé jusqu'à sa prochaine
          connexion.
        </p>
      </Card>

      <Card title="Comptes sensibles">
        <div className="filters">
          <div className="segmented" role="group" aria-label="Type de compte">
            {[
              ["", `Tous (${data?.accounts.length ?? 0})`],
              ["admin", `Administrateurs (${count("admin")})`],
              ["service", `Comptes de service (${count("service")})`],
            ].map(([v, l]) => (
              <button key={v} className={role === v ? "active" : ""} onClick={() => setRole(v)}>
                {l}
              </button>
            ))}
          </div>
          <input type="search" placeholder="Rechercher un compte" value={search} onChange={(e) => setSearch(e.target.value)} />
          <span className="spacer" />
          <span className="muted small">
            {data?.sync
              ? data.sync.error
                ? `Lecture de l'AD en échec ${timeAgo(data.sync.at)} : ${data.sync.error}`
                : `AD lu ${timeAgo(data.sync.at)} : ${data.sync.admin} admin(s), ${data.sync.service} compte(s) de service`
              : data?.ad_configured
                ? "AD pas encore lu"
                : "Compte LDAPS non configuré : seuls les motifs de noms s'appliquent"}
          </span>
          {user?.role === "admin" && data?.ad_configured && (
            <button type="button" disabled={syncing} onClick={sync}>
              {syncing ? "Lecture…" : "Relire l'AD"}
            </button>
          )}
        </div>
        {data && !accounts.length ? (
          <Empty>
            Aucun compte sensible identifié. Configurez le compte LDAPS (Paramètres › Annuaire AD) ou des motifs de noms
            (Paramètres › Détection : {[...data.patterns.admin, ...data.patterns.service].join(", ") || "aucun"}).
          </Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Compte</th>
                <th>Type</th>
                <th>Dernière connexion vue</th>
                <th className="num">Connexions 7 j</th>
                <th className="num">Échecs 7 j</th>
                <th className="num">Verrouillages 7 j</th>
                <th className="num">Postes 7 j</th>
                <th>Points d'attention</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((a) => (
                <tr key={a.name} className={a.disabled ? "disabled" : ""}>
                  <td>
                    <Link to={`/events?user=${encodeURIComponent(a.name)}`}>{a.name}</Link>
                    {a.disabled && <span className="muted small"> (désactivé)</span>}
                    {(a.display_name || a.description) && (
                      <div className="muted small">{[a.display_name, a.description].filter(Boolean).join(" · ")}</div>
                    )}
                  </td>
                  <td>
                    {roleTags(a.roles)}
                    <div className="muted small">{a.source === "ad" ? "lu dans l'AD" : "motif de nom"}</div>
                  </td>
                  <td className="small">
                    {a.last_logon ? (
                      <>
                        <span title={formatDate(a.last_logon)}>{timeAgo(a.last_logon)}</span>
                        <div className="muted">
                          {a.last_host} · {SERVICE_LABEL[a.last_service] ?? a.last_service}
                        </div>
                      </>
                    ) : a.ad_last_logon ? (
                      <span className="muted" title="Date répliquée par l'AD (précision de quelques jours)">
                        AD : {formatDate(a.ad_last_logon)}
                      </span>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td className="num">{formatNumber(a.logons_7d)}</td>
                  <td className={`num ${a.failures_7d >= 5 ? "text-bad" : ""}`}>{formatNumber(a.failures_7d)}</td>
                  <td className={`num ${a.lockouts_7d ? "text-bad" : ""}`}>{formatNumber(a.lockouts_7d)}</td>
                  <td className="num">{formatNumber(a.hosts_7d)}</td>
                  <td className="small">
                    <Warnings a={a} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
