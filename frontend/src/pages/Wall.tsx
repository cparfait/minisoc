import { useEffect, useRef, useState } from "react";
import { ApiError, api } from "../api";
import CountryBars from "../components/CountryBars";
import { HourlyBars } from "../components/charts";
import { SEVERITY_LABEL, formatNumber, moduleLabel, timeAgo } from "../labels";
import type { Overview, Severity, Source, Verdict } from "../types";

interface WallAlert {
  id: number;
  severity: Severity;
  title: string;
  rule_id: string;
  status: "new" | "in_progress";
  assignee: string | null;
  count: number;
  first_seen: string;
  last_seen: string;
  verdict: Verdict | null;
  verdict_label: string | null;
}

interface WallData {
  screen: string;
  generated_at: string;
  open_by_severity: Record<Severity, number>;
  new_24h: number;
  unhandled: number;
  unhandled_critical: number;
  alerts: WallAlert[];
  sources: Source[];
  top_attackers: Overview["top_attackers"];
  auth_failures_hourly: Overview["auth_failures_hourly"];
  failures_by_country: Overview["failures_by_country"];
  clickhouse_error: boolean;
}

const REFRESH_MS = 15000;
const STALE_MS = 60000;

/** Écran mural : lecture seule, lisible à distance, rafraîchi automatiquement. */
export default function Wall() {
  const [data, setData] = useState<WallData | null>(null);
  const [lastOk, setLastOk] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());
  const [pointerActive, setPointerActive] = useState(false);
  const pointerTimer = useRef<number | undefined>(undefined);
  const wakeLock = useRef<{ release: () => Promise<void> } | null>(null);

  // Curseur et bouton « Menu » visibles seulement quand la souris bouge (affichage permanent épuré)
  const onPointerMove = () => {
    setPointerActive(true);
    window.clearTimeout(pointerTimer.current);
    pointerTimer.current = window.setTimeout(() => setPointerActive(false), 3000);
  };

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const result = await api<WallData>("/wall/overview");
        if (cancelled) return;
        setData(result);
        setLastOk(Date.now());
        setError(null);
      } catch (e) {
        if (!cancelled) setError(e instanceof ApiError && e.status === 401 ? "unauthorized" : String(e));
      }
    };
    const start = async () => {
      // Jeton transmis dans le fragment (#token=…) : jamais envoyé au serveur ni conservé dans l'historique
      const token = new URLSearchParams(window.location.hash.slice(1)).get("token");
      if (token) {
        window.history.replaceState(null, "", window.location.pathname);
        try {
          await api("/wall/session", { method: "POST", body: { token } });
        } catch {
          setError("unauthorized");
          return;
        }
      }
      await load();
    };
    start();
    const refresh = window.setInterval(load, REFRESH_MS);
    const clock = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {
      cancelled = true;
      window.clearInterval(refresh);
      window.clearInterval(clock);
    };
  }, []);

  // Empêche la mise en veille de l'écran quand le navigateur le permet
  useEffect(() => {
    const nav = navigator as Navigator & { wakeLock?: { request: (t: "screen") => Promise<{ release: () => Promise<void> }> } };
    const acquire = () => nav.wakeLock?.request("screen").then((l) => (wakeLock.current = l)).catch(() => undefined);
    acquire();
    const onVisible = () => document.visibilityState === "visible" && acquire();
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      document.removeEventListener("visibilitychange", onVisible);
      wakeLock.current?.release().catch(() => undefined);
    };
  }, []);

  if (error === "unauthorized" && !data) {
    return (
      <div className="wall wall-message">
        <h1>Écran non autorisé</h1>
        <p>Demandez un lien d'affichage à l'administrateur :</p>
        <code>python -m minisoc.cli create-display-token --name "…" --ip &lt;IP de l'écran&gt;</code>
      </div>
    );
  }
  if (!data) return <div className="wall wall-message">Chargement…</div>;

  const stale = now - lastOk > STALE_MS;
  const level = data.unhandled_critical > 0 ? "critical" : data.open_by_severity.critical + data.open_by_severity.high > 0 ? "warning" : "ok";
  const statusText =
    level === "critical"
      ? `${data.unhandled_critical} alerte(s) critique(s) non prise(s) en charge`
      : level === "warning"
        ? "Alertes ouvertes en cours de traitement"
        : "Situation normale";
  const clock = new Date(now);

  return (
    <div
      className={`wall level-${level} ${pointerActive ? "pointer-active" : ""}`}
      onMouseMove={onPointerMove}
      onDoubleClick={() => document.documentElement.requestFullscreen?.().catch(() => undefined)}
    >
      <a href="/" className="wall-menu" onClick={() => document.fullscreenElement && document.exitFullscreen()}>
        ← Menu
      </a>
      <header className="wall-header">
        <div className="wall-brand">
          <img src="/favicon.svg" alt="" />
          Mini-SOC
        </div>
        <div className={`wall-status status-${level}`}>{statusText}</div>
        <div className="wall-clock">
          <strong>{clock.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}</strong>
          <span>{clock.toLocaleDateString("fr-FR", { weekday: "long", day: "numeric", month: "long" })}</span>
        </div>
      </header>

      {stale && (
        <div className="wall-stale" role="alert">
          Données non mises à jour depuis {timeAgo(new Date(lastOk).toISOString()).replace("il y a ", "")} : vérifier la
          connexion de l'écran
        </div>
      )}

      <section className="wall-kpis">
        <Kpi value={data.open_by_severity.critical} label="Critiques ouvertes" tone="critical" />
        <Kpi value={data.open_by_severity.high} label="Hautes ouvertes" tone="high" />
        <Kpi value={data.unhandled} label="Non prises en charge" tone={data.unhandled ? "critical" : "ok"} />
        <Kpi value={data.new_24h} label="Nouvelles en 24 h" tone="neutral" />
      </section>

      <main className="wall-main">
        <section className="wall-panel wall-alerts">
          <h2>Alertes à traiter</h2>
          {data.alerts.length === 0 ? (
            <p className="wall-empty">Aucune alerte haute ou critique ouverte</p>
          ) : (
            <ul>
              {data.alerts.map((a) => (
                <li key={a.id} className={`sev-bar-${a.severity}`}>
                  <span className={`badge sev-${a.severity}`}>{SEVERITY_LABEL[a.severity]}</span>
                  <div className="wall-alert-body">
                    <div className="wall-alert-title">{a.title}</div>
                    <div className="wall-alert-meta">
                      {a.rule_id} · {formatNumber(a.count)} occ. · {timeAgo(a.last_seen)}
                      {a.verdict_label && <span className={`badge verdict-${a.verdict}`}>{a.verdict_label}</span>}
                    </div>
                  </div>
                  <span className={`wall-handling ${a.status}`}>
                    {a.status === "new" ? "À prendre en charge" : `En cours${a.assignee ? ` · ${a.assignee}` : ""}`}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <aside className="wall-side">
          <section className="wall-panel">
            <h2>Sources</h2>
            <div className="wall-sources">
              {data.sources.length === 0 && <p className="wall-empty">Aucune source</p>}
              {data.sources.map((s) => (
                <div key={s.module} className={`wall-source source-${s.status}`}>
                  <i />
                  <span>{moduleLabel(s.module)}</span>
                  <small>{s.status === "silent" ? "SILENCIEUSE" : timeAgo(s.last_seen)}</small>
                </div>
              ))}
            </div>
          </section>
          <section className="wall-panel">
            <h2>Échecs d'authentification · 24 h</h2>
            {data.clickhouse_error ? <p className="wall-empty">Indisponible</p> : <HourlyBars points={data.auth_failures_hourly} />}
          </section>
          {data.failures_by_country?.length > 0 && (
            <section className="wall-panel">
              <h2>Origine des échecs · 24 h</h2>
              <CountryBars rows={data.failures_by_country.slice(0, 6)} />
            </section>
          )}
          <section className="wall-panel">
            <h2>IP les plus actives en échec · 24 h</h2>
            {data.top_attackers.length === 0 ? (
              <p className="wall-empty">Aucune</p>
            ) : (
              <table className="wall-table">
                <tbody>
                  {data.top_attackers.map((t) => (
                    <tr key={t.ip}>
                      <td className="mono">
                        {t.ip}
                        {t.country && <span className="geo-tag">{t.country}</span>}
                      </td>
                      <td className="num">{formatNumber(t.failures)}</td>
                      <td className="num muted">{t.users} cpt</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </aside>
      </main>
      <footer className="wall-footer">
        {data.screen} · mise à jour {new Date(data.generated_at).toLocaleTimeString("fr-FR")} · double-clic : plein écran
      </footer>
    </div>
  );
}

function Kpi({ value, label, tone }: { value: number; label: string; tone: string }) {
  return (
    <div className={`wall-kpi tone-${tone} ${value > 0 ? "has-value" : ""}`}>
      <strong>{formatNumber(value)}</strong>
      <span>{label}</span>
    </div>
  );
}
