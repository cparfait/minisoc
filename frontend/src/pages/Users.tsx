import { Users as UsersIcon } from "lucide-react";
import { useState } from "react";
import { api } from "../api";
import { useUser } from "../App";
import { ErrorBanner, PageHeader } from "../components/ui";
import { usePolling } from "../hooks";
import { formatDate } from "../labels";

interface AdminUser {
  id: number;
  username: string;
  display_name: string;
  email: string;
  auth_source: "local" | "ldap";
  role: "admin" | "analyst" | "viewer";
  active: boolean;
  mfa_enrolled: boolean;
  last_login_at: string | null;
  active_sessions: number;
}

const ROLE_LABEL = { admin: "Administrateur", analyst: "Analyste", viewer: "Lecteur" };

export default function Users() {
  const me = useUser();
  const { data, error, reload } = usePolling(() => api<{ items: AdminUser[] }>("/admin/users"), [], 0);
  const [actionError, setActionError] = useState<string | null>(null);

  const act = async (fn: () => Promise<unknown>) => {
    setActionError(null);
    try {
      await fn();
      await reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <>
      <PageHeader title="Utilisateurs" icon={UsersIcon} subtitle="Comptes, rôles et double authentification" />
      <p className="muted">
        Les comptes AD sont créés à leur première connexion ; leur rôle suit leurs groupes AD. Les comptes locaux (secours)
        se créent avec <code>python -m minisoc.cli create-user</code>.
      </p>
      <ErrorBanner error={error ?? actionError} />
      <table>
        <thead>
          <tr>
            <th>Compte</th>
            <th>Origine</th>
            <th>Rôle</th>
            <th>Double authentification</th>
            <th>Dernière connexion</th>
            <th>Sessions</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {data?.items.map((u) => (
            <tr key={u.id} className={u.active ? "" : "disabled"}>
              <td>
                <strong>{u.username}</strong>
                {u.display_name && <div className="muted small">{u.display_name}</div>}
              </td>
              <td>
                <span className={`badge ${u.auth_source === "ldap" ? "status-new" : "status-false_positive"}`}>
                  {u.auth_source === "ldap" ? "Active Directory" : "Local"}
                </span>
              </td>
              <td>
                {u.auth_source === "local" && u.id !== undefined ? (
                  <select value={u.role} disabled={u.username === me?.username}
                    onChange={(e) => act(() => api(`/admin/users/${u.id}`, { method: "PATCH", body: { role: e.target.value } }))}>
                    {Object.entries(ROLE_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                  </select>
                ) : (
                  ROLE_LABEL[u.role]
                )}
              </td>
              <td>{u.mfa_enrolled ? <span className="text-good">activée</span> : <span className="muted">à enrôler</span>}</td>
              <td>{formatDate(u.last_login_at)}</td>
              <td className="num">{u.active_sessions}</td>
              <td className="nowrap">
                {u.username !== me?.username && (
                  <>
                    <button className="link" onClick={() => act(() => api(`/admin/users/${u.id}`, { method: "PATCH", body: { active: !u.active } }))}>
                      {u.active ? "Désactiver" : "Réactiver"}
                    </button>{" "}
                    ·{" "}
                    <button className="link" onClick={() => window.confirm(`Réinitialiser la double authentification de ${u.username} ? Ses sessions seront fermées et il devra scanner un nouveau QR code.`) &&
                      act(() => api(`/admin/users/${u.id}/reset-mfa`, { method: "POST" }))}>
                      Réinitialiser le MFA
                    </button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
