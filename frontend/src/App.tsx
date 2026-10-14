import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import {
  Ban, ExternalLink, FileChartColumn, FilterX, LayoutDashboard, ListChecks, LogOut, MonitorPlay, Moon, Plug, Radar,
  ScrollText, Settings as SettingsIcon, ShieldAlert, Siren, Sparkles, Sun, UserCog, Users as UsersIcon,
  type LucideIcon, Boxes, Bug, Crosshair, PanelLeftClose, PanelLeftOpen, Search as SearchIcon,
} from "lucide-react";
import { api } from "./api";
import { applyTheme, storedTheme, type Theme } from "./theme";
import type { User } from "./types";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";
import Events from "./pages/Events";
import Integrations from "./pages/Integrations";
import Rules from "./pages/Rules";
import Exceptions from "./pages/Exceptions";
import Wall from "./pages/Wall";
import Settings from "./pages/Settings";
import Users from "./pages/Users";
import Assistant from "./pages/Assistant";
import Blocks from "./pages/Blocks";
import Veille from "./pages/Veille";
import Vulnerabilities from "./pages/Vulnerabilities";
import Accounts from "./pages/Accounts";
import Incidents from "./pages/Incidents";
import Reports from "./pages/Reports";
import IncidentDetail from "./pages/IncidentDetail";
import Assets from "./pages/Assets";
import AssetDetail from "./pages/AssetDetail";
import Iocs from "./pages/Iocs";
import Search from "./pages/Search";

const UserContext = createContext<User | null>(null);
export const useUser = () => useContext(UserContext);
export const canEdit = (user: User | null) => user?.role === "admin" || user?.role === "analyst";

type NavItem = { to: string; label: string; icon: LucideIcon; end?: boolean; badge?: "alerts" | "incidents" };

const NAV_GROUPS: { title: string; items: NavItem[]; role?: "edit" | "admin" }[] = [
  {
    title: "Supervision",
    items: [
      { to: "/", label: "Tableau de bord", icon: LayoutDashboard, end: true },
      { to: "/alerts", label: "Alertes", icon: Siren, badge: "alerts" },
      { to: "/incidents", label: "Incidents", icon: ShieldAlert, badge: "incidents" },
      { to: "/events", label: "Événements", icon: ScrollText },
    ],
  },
  {
    title: "Analyse",
    items: [
      { to: "/search", label: "Recherche", icon: SearchIcon },
      { to: "/assets", label: "Inventaire", icon: Boxes },
      { to: "/accounts", label: "Comptes AD", icon: UserCog },
      { to: "/cve", label: "Vulnérabilités", icon: Bug },
      { to: "/veille", label: "Veille", icon: Radar },
      { to: "/reports", label: "Rapports", icon: FileChartColumn },
    ],
  },
  {
    title: "Détection et réponse",
    items: [
      { to: "/integrations", label: "Intégrations", icon: Plug },
      { to: "/rules", label: "Règles", icon: ListChecks },
      { to: "/iocs", label: "IOC", icon: Crosshair },
      { to: "/exceptions", label: "Exceptions", icon: FilterX },
      { to: "/blocks", label: "Blocages", icon: Ban },
    ],
  },
];
const ADMIN_NAV: NavItem[] = [
  { to: "/users", label: "Utilisateurs", icon: UsersIcon },
  { to: "/settings", label: "Paramètres", icon: SettingsIcon },
];
const WALL_LINK = "/wall";
const ROLE_LABEL: Record<string, string> = { admin: "Administrateur", analyst: "Analyste", viewer: "Lecteur" };

/** Compteurs du menu : alertes nouvelles et incidents en cours (rafraîchis toutes les 30 s). */
function useNavCounts() {
  const [counts, setCounts] = useState<{ alerts: number; incidents: number }>({ alerts: 0, incidents: 0 });
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [a, i] = await Promise.all([
          api<{ total: number }>("/alerts?status=new&limit=1"),
          api<{ by_status: Record<string, number> }>("/incidents?status=open"),
        ]);
        const inc = ["open", "investigating", "contained"].reduce((n, k) => n + (i.by_status[k] ?? 0), 0);
        if (alive) setCounts({ alerts: a.total, incidents: inc });
      } catch {
        // compteurs facultatifs : le menu reste utilisable sans eux
      }
    };
    load();
    const timer = window.setInterval(load, 30000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);
  return counts;
}

function NavEntry({ item, count }: { item: NavItem; count?: number }) {
  const Icon = item.icon;
  return (
    <NavLink to={item.to} end={item.end} className={({ isActive }) => (isActive ? "active" : "")} title={item.label}>
      <Icon size={18} strokeWidth={1.9} />
      <span className="nav-label">{item.label}</span>
      {count ? <span className="nav-badge">{count > 99 ? "99+" : count}</span> : null}
    </NavLink>
  );
}

export default function App() {
  // L'écran mural a son propre mode d'accès (jeton d'affichage), hors session interactive
  if (window.location.pathname.startsWith("/wall")) {
    document.documentElement.dataset.theme = "dark"; // écran de supervision : toujours sombre
    return <Wall />;
  }
  return <InteractiveApp />;
}

function InteractiveApp() {
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(true);
  const [theme, setTheme] = useState<Theme>(storedTheme());

  const refresh = useCallback(async () => {
    try {
      setUser(await api<User>("/auth/me"));
    } catch {
      setUser(null);
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const onUnauthorized = () => setUser(null);
    window.addEventListener("minisoc:unauthorized", onUnauthorized);
    return () => window.removeEventListener("minisoc:unauthorized", onUnauthorized);
  }, [refresh]);

  if (checking) return <div className="splash">Chargement…</div>;
  if (!user) return <Login onLogin={setUser} />;
  return <Shell user={user} setUser={setUser} theme={theme} setTheme={setTheme} />;
}

function Shell({ user, setUser, theme, setTheme }: {
  user: User;
  setUser: (u: User | null) => void;
  theme: Theme;
  setTheme: (t: Theme) => void;
}) {
  const counts = useNavCounts();
  // Menu rétractable (icônes seules), mémorisé sur ce poste
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("minisoc.sidebar.collapsed") === "1");
  const toggleSidebar = () => {
    localStorage.setItem("minisoc.sidebar.collapsed", collapsed ? "0" : "1");
    setCollapsed(!collapsed);
  };

  const toggleTheme = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    applyTheme(next);
    setTheme(next);
  };

  const logout = async () => {
    await api("/auth/logout", { method: "POST" }).catch(() => undefined);
    setUser(null);
  };

  return (
    <UserContext.Provider value={user}>
      <div className={`layout ${collapsed ? "sidebar-collapsed" : ""}`}>
        <aside className="sidebar">
          <div className="brand">
            <img src="/favicon.svg" alt="" width={34} height={34} />
            <div className="brand-text">
              Mini-SOC
              <small>Supervision de la sécurité</small>
            </div>
          </div>
          <button
            type="button"
            className="sidebar-toggle"
            onClick={toggleSidebar}
            title={collapsed ? "Déplier le menu" : "Replier le menu"}
            aria-label={collapsed ? "Déplier le menu" : "Replier le menu"}
            aria-expanded={!collapsed}
          >
            {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          </button>
          <nav>
            {NAV_GROUPS.map((group) => (
              <div key={group.title} className="nav-group">
                <div className="nav-section">{group.title}</div>
                {group.items.map((item) => (
                  <NavEntry key={item.to} item={item} count={item.badge ? counts[item.badge] : undefined} />
                ))}
                {group.title === "Analyse" && canEdit(user) && (
                  <NavEntry item={{ to: "/assistant", label: "Assistant IA", icon: Sparkles }} />
                )}
              </div>
            ))}
            {user.role === "admin" && (
              <div className="nav-group">
                <div className="nav-section">Administration</div>
                {ADMIN_NAV.map((item) => (
                  <NavEntry key={item.to} item={item} />
                ))}
              </div>
            )}
            <a href={WALL_LINK} target="_blank" rel="noopener noreferrer" title="Écran mural">
              <MonitorPlay size={18} strokeWidth={1.9} />
              <span className="nav-label">Écran mural</span>
              <ExternalLink size={14} className="nav-external" />
            </a>
          </nav>
          <div className="sidebar-footer">
            <div className="user-card">
              <span className="avatar">{user.username.slice(0, 2)}</span>
              <div className="user-meta">
                <strong title={user.username}>{user.username}</strong>
                <span>{ROLE_LABEL[user.role] ?? user.role}</span>
              </div>
              <button type="button" className="icon-button" onClick={toggleTheme}
                title={theme === "dark" ? "Thème clair" : "Thème sombre"} aria-label="Changer de thème">
                {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
              </button>
              <button type="button" className="icon-button" onClick={logout} title="Déconnexion" aria-label="Déconnexion">
                <LogOut size={17} />
              </button>
            </div>
          </div>
        </aside>
        <main className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/alerts/:id" element={<AlertDetail />} />
            <Route path="/events" element={<Events />} />
            <Route path="/accounts" element={<Accounts />} />
            <Route path="/search" element={<Search />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/assets/:kind/:name" element={<AssetDetail />} />
            <Route path="/iocs" element={<Iocs />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/integrations" element={<Integrations />} />
            <Route path="/sources" element={<Navigate to="/integrations" replace />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/exceptions" element={<Exceptions />} />
            <Route path="/blocks" element={<Blocks />} />
            <Route path="/veille" element={<Veille />} />
            <Route path="/cve" element={<Vulnerabilities />} />
            <Route path="/cve/:code" element={<Vulnerabilities />} />
            {canEdit(user) && <Route path="/assistant" element={<Assistant />} />}
            {user.role === "admin" && <Route path="/users" element={<Users />} />}
            {user.role === "admin" && <Route path="/settings" element={<Settings />} />}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </UserContext.Provider>
  );
}
