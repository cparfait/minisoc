import { ListOrdered, Volume2, VolumeX } from "lucide-react";
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
  vpn: {
    summary: { failures?: number; users_failed?: number; ips_failed?: number; masked?: number; successes?: number; successes_abroad?: number };
    services: { service: string; failures: number; successes: number }[];
    targeted: { user: string; failures: number }[];
    recent: { ts: string; service: string; user: string; ip: string; country: string; outcome: string; name?: string }[];
  } | null;
  vulnerabilities: {
    assets: number;
    with_kev: number;
    kev_cves: number;
    eol: number;
    with_prioritized: number;
    exposed: { name: string; server: boolean; kev: number; prioritized: number; os: string; eol_passed: boolean }[];
  } | null;
  newest: (WallAlert & { created_at: string; module: string })[];
  /** Réglages communs (Paramètres › Écran mural). */
  config?: { pages: Page[]; rotation: number; flash_min_severity: string; sound_default: boolean };
}

const SERVICE: Record<string, string> = {
  ssl_vpn: "VPN SSL", ipsec: "VPN IPsec", l2tp: "L2TP", user_portal: "Portail VPN", admin_console: "Administration",
};
/** Écrans qui défilent ; « alertes » est toujours présent, les autres seulement s'ils ont des données. */
type Page = "alertes" | "vpn" | "auth" | "vuln" | "sources";
const PAGE_LABEL: Record<Page, string> = {
  alertes: "Alertes", vpn: "Accès VPN", auth: "Authentifications", vuln: "Vulnérabilités", sources: "Sources",
};
const OVERLAY_MS = 30000; // affichage d'une nouvelle alerte (haute ou critique)
const SOUND_KEY = "minisoc.wall.sound";
const LIMIT_KEY = "minisoc.wall.limit";
const LIMITS = [10, 20, 30, 50];

/** Carillon discret (deux notes douces), joué sans fichier son par l'API Web Audio du navigateur. */
function chime(ctx: AudioContext) {
  const now = ctx.currentTime;
  [
    [880, 0],
    [660, 0.22],
  ].forEach(([freq, delay]) => {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.value = freq;
    gain.gain.setValueAtTime(0, now + delay);
    gain.gain.linearRampToValueAtTime(0.06, now + delay + 0.03);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + delay + 0.5);
    osc.connect(gain).connect(ctx.destination);
    osc.start(now + delay);
    osc.stop(now + delay + 0.55);
  });
}
const SEEN_KEY = "minisoc.wall.lastAlertId";

/** Durée imposée à un écran précis par son adresse (#rotation=30, 0 = pas de défilement) ; sinon le réglage commun
 * de Paramètres › Écran mural. */
function readRotation(): number | null {
  const hash = new URLSearchParams(window.location.hash.slice(1));
  const fromHash = hash.get("rotation");
  if (fromHash !== null) localStorage.setItem("minisoc.wall.rotation", fromHash);
  const raw = fromHash ?? localStorage.getItem("minisoc.wall.rotation");
  const value = raw === null ? NaN : Number(raw);
  return Number.isFinite(value) && value >= 0 ? value : null;
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
  const [rotationOverride] = useState(readRotation);
  const [pageIndex, setPageIndex] = useState(0);
  const [paused, setPaused] = useState(false);
  const [flash, setFlash] = useState<WallData["newest"]>([]);
  const lastSeenId = useRef<number | null>(sessionStorage.getItem(SEEN_KEY) ? Number(sessionStorage.getItem(SEEN_KEY)) : null);
  const flashTimer = useRef<number | undefined>(undefined);
  // Son : choix fait sur cet écran, sinon le réglage commun (appliqué au premier chargement)
  const [soundOn, setSoundOn] = useState(() => localStorage.getItem(SOUND_KEY) === "1");
  // Éléments par liste : réglé sur chaque écran (à côté de l'icône du son), mémorisé
  const [limit, setLimit] = useState(() => Number(localStorage.getItem(LIMIT_KEY)) || 30);
  const limitRef = useRef(limit);
  const loadNow = useRef<(() => void) | undefined>(undefined);
  const soundRef = useRef(soundOn);
  const audio = useRef<AudioContext | null>(null);
  const [soundBlocked, setSoundBlocked] = useState(false);

  /** Le navigateur n'autorise le son qu'après une action sur la page : le contexte audio est créé au premier clic. */
  const ensureAudio = () => {
    if (!audio.current) {
      const Ctx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      if (!Ctx) return null;
      audio.current = new Ctx();
    }
    if (audio.current.state === "suspended") audio.current.resume().catch(() => undefined);
    return audio.current;
  };
  const toggleSound = () => {
    const next = !soundOn;
    setSoundOn(next);
    soundRef.current = next;
    localStorage.setItem(SOUND_KEY, next ? "1" : "0");
    if (next) {
      const ctx = ensureAudio();
      if (ctx) chime(ctx); // aperçu du son à l'activation
      setSoundBlocked(false);
    }
  };
  const playAlertSound = () => {
    if (!soundRef.current) return;
    const ctx = audio.current;
    if (!ctx || ctx.state !== "running") {
      setSoundBlocked(true); // son activé mais pas encore autorisé par le navigateur : toucher l'écran une fois
      return;
    }
    chime(ctx);
  };

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
        const result = await api<WallData>(`/wall/overview?limit=${limitRef.current}`);
        if (cancelled) return;
        // Nouvelle alerte haute ou critique depuis le dernier passage : affichée tout de suite, en plein écran
        const maxId = Math.max(0, ...(result.newest ?? []).map((a) => a.id));
        if (lastSeenId.current === null) {
          lastSeenId.current = maxId; // premier chargement : rien d'ancien n'est « nouveau »
        } else if (maxId > lastSeenId.current) {
          const fresh = result.newest.filter((a) => a.id > (lastSeenId.current ?? 0));
          lastSeenId.current = maxId;
          setFlash(fresh);
          playAlertSound();
          window.clearTimeout(flashTimer.current);
          flashTimer.current = window.setTimeout(() => setFlash([]), OVERLAY_MS);
        }
        sessionStorage.setItem(SEEN_KEY, String(lastSeenId.current));
        if (localStorage.getItem(SOUND_KEY) === null && result.config?.sound_default && !soundRef.current) {
          soundRef.current = true;
          setSoundOn(true);
        }
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
    loadNow.current = load;
    start();
    const refresh = window.setInterval(load, REFRESH_MS);
    const clock = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {
      cancelled = true;
      window.clearInterval(refresh);
      window.clearInterval(clock);
    };
  }, []);

  const rotation = rotationOverride ?? data?.config?.rotation ?? 20;
  const pages: Page[] = data
    ? (data.config?.pages?.length ? data.config.pages : (["alertes", "vpn", "auth", "vuln", "sources"] as Page[])).filter(
        (p) =>
          p === "alertes" ||
          (p === "vpn" && data.vpn && (data.vpn.summary.failures ?? 0) + (data.vpn.summary.successes ?? 0) > 0) ||
          (p === "auth" && !data.clickhouse_error) ||
          (p === "vuln" && data.vulnerabilities) ||
          // Écran « Sources » : seulement s'il y a une source en défaut (sinon rien à montrer)
          (p === "sources" && data.sources.some((x) => x.status === "silent")),
      )
    : ["alertes"];
  const page = pages[pageIndex % pages.length] ?? "alertes";
  const holding = paused || pointerActive || flash.length > 0;

  useEffect(() => {
    if (!rotation || holding || pages.length < 2) return;
    const timer = window.setTimeout(() => setPageIndex((i) => (i + 1) % pages.length), rotation * 1000);
    return () => window.clearTimeout(timer);
  }, [rotation, holding, pageIndex, pages.length]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "ArrowRight") setPageIndex((i) => (i + 1) % Math.max(pages.length, 1));
      else if (e.key === "ArrowLeft") setPageIndex((i) => (i - 1 + Math.max(pages.length, 1)) % Math.max(pages.length, 1));
      else if (e.key === " ") setPaused((v) => !v);
      else if (e.key === "Escape") setFlash([]);
      else return;
      e.preventDefault();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [pages.length]);

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
      onClick={() => {
        if (soundRef.current && ensureAudio()?.state !== "suspended") setSoundBlocked(false);
      }}
      onDoubleClick={() => document.documentElement.requestFullscreen?.().catch(() => undefined)}
    >
      <a href="/" className="wall-menu" onClick={() => document.fullscreenElement && document.exitFullscreen()}>
        ← Menu
      </a>
      {/* Une seule ligne d'en-tête : logo, écran affiché, état, commandes, heure */}
      <header className="wall-header wall-header-compact">
        <div className="wall-brand">
          <img src="/favicon.svg" alt="" />
          <h1 className="wall-page-title">{PAGE_LABEL[page]}</h1>
        </div>
        <div className={`wall-status status-${level}`}>{statusText}</div>
        <div className="wall-controls">
          <label className="wall-limit" title="Éléments par liste" onClick={(e) => e.stopPropagation()}>
            <ListOrdered size={15} aria-hidden />
            <select
              value={limit}
              aria-label="Éléments par liste"
              onChange={(e) => {
                const value = Number(e.target.value);
                localStorage.setItem(LIMIT_KEY, String(value));
                limitRef.current = value;
                setLimit(value);
                loadNow.current?.(); // rechargement immédiat avec le nouveau nombre
              }}
            >
              {LIMITS.map((n) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className={`wall-sound ${soundOn ? "on" : ""}`}
            onClick={(e) => {
              e.stopPropagation();
              toggleSound();
            }}
            title={soundOn ? "Son activé : cliquer pour couper" : "Son coupé : cliquer pour activer un son discret à chaque nouvelle alerte"}
            aria-label={soundOn ? "Couper le son" : "Activer le son"}
          >
            {soundOn ? <Volume2 size={16} /> : <VolumeX size={16} />}
          </button>
          <div className="wall-clock">
            <strong>{clock.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}</strong>
            <span>{clock.toLocaleDateString("fr-FR", { weekday: "short", day: "numeric", month: "short" })}</span>
          </div>
        </div>
      </header>

      {stale && (
        <div className="wall-stale" role="alert">
          Données non mises à jour depuis {timeAgo(new Date(lastOk).toISOString()).replace("il y a ", "")} : vérifier la
          connexion de l'écran
        </div>
      )}

      {rotation > 0 && pages.length > 1 && (
        <div className="wall-progress">
          <span key={`${pageIndex}-${holding}`} style={{ animationDuration: `${rotation}s`, animationPlayState: holding ? "paused" : "running" }} />
        </div>
      )}
      {soundOn && soundBlocked && <div className="wall-sound-hint">Touchez l'écran une fois pour autoriser le son</div>}

      {page === "alertes" && (
        <>
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
              <AutoScroll>
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
              </AutoScroll>
            )}
          </section>

          <aside className="wall-side">
            <section className="wall-panel">
              <h2>Sources en défaut</h2>
              <SilentSources sources={data.sources} />
            </section>
            <section className="wall-panel">
              <h2>Adresses les plus actives en échec · 24 h</h2>
              {data.top_attackers.length === 0 ? (
                <p className="wall-empty">Aucune</p>
              ) : (
                <AutoScroll className="wall-rows">
                  {data.top_attackers.map((t) => (
                    <div key={t.ip} className="wall-row wall-row-ip3">
                      <span className="wall-row-main">
                        <strong>{t.name || t.ip}</strong>
                        <small>
                          {t.name ? `${t.ip} · ` : ""}
                          {t.users} compte{t.users > 1 ? "s" : ""}
                        </small>
                      </span>
                      <Country code={t.country ?? ""} />
                      <span className="wall-row-count">{formatNumber(t.failures)}</span>
                    </div>
                  ))}
                </AutoScroll>
              )}
            </section>
          </aside>
        </main>
        </>
      )}

      {page === "vpn" && data.vpn && <VpnPage vpn={data.vpn} />}
      {page === "auth" && <AuthPage data={data} />}
      {page === "vuln" && data.vulnerabilities && <VulnPage v={data.vulnerabilities} />}
      {page === "sources" && <SourcesPage sources={data.sources} />}

      {flash.length > 0 && (
        <div className={`wall-flash sev-${flash[0].severity}`} role="alert" onClick={() => setFlash([])}>
          <div className="wall-flash-box">
            <div className="wall-flash-head">{flash.length > 1 ? `${flash.length} NOUVELLES ALERTES` : "NOUVELLE ALERTE"}</div>
            {flash.slice(0, 3).map((a) => (
              <div key={a.id} className="wall-flash-alert">
                <span className={`badge sev-${a.severity}`}>{SEVERITY_LABEL[a.severity]}</span>
                <div className="wall-flash-title">{a.title}</div>
                <div className="wall-flash-meta">
                  {a.rule_id}
                  {a.module && ` · ${moduleLabel(a.module)}`} · {new Date(a.created_at).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}
                </div>
              </div>
            ))}
            <div className="wall-flash-hint">Toucher l'écran ou Échap pour fermer · reprise du défilement dans 30 s</div>
          </div>
        </div>
      )}

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

/** Temps écoulé, court et sans retour à la ligne (« 18 min », « 2 h », « 3 j »). */
function ago(iso: string): string {
  const minutes = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  if (minutes < 1) return "à l'instant";
  if (minutes < 60) return `${minutes} min`;
  if (minutes < 48 * 60) return `${Math.round(minutes / 60)} h`;
  return `${Math.round(minutes / 1440)} j`;
}

function Country({ code }: { code: string }) {
  return code ? <span className="wall-cc">{code}</span> : null;
}

function VpnPage({ vpn }: { vpn: NonNullable<WallData["vpn"]> }) {
  const sm = vpn.summary;
  const maxService = Math.max(1, ...vpn.services.map((x) => x.failures + x.successes));
  return (
    <>
      <section className="wall-kpis">
        <Kpi value={sm.failures ?? 0} label="Échecs VPN · 24 h" tone={(sm.failures ?? 0) > 50 ? "high" : "neutral"} />
        <Kpi value={sm.users_failed ?? 0} label="Comptes visés" tone="neutral" />
        <Kpi value={sm.ips_failed ?? 0} label="Adresses en échec" tone="neutral" />
        <Kpi value={sm.successes_abroad ?? 0} label="Réussies hors de France" tone={sm.successes_abroad ? "critical" : "ok"} />
      </section>
      <main className="wall-main">
        <section className="wall-panel">
          <h2>Échecs et connexions depuis l'étranger</h2>
          {vpn.recent.length === 0 ? (
            <p className="wall-empty">Aucun échec ni connexion depuis l'étranger</p>
          ) : (
            <AutoScroll className="wall-rows">
              {vpn.recent.map((r, i) => (
                <div key={`${r.ts}-${i}`} className={`wall-row ${r.outcome === "failure" ? "is-fail" : "is-ok"}`}>
                  <span className={`wall-pill ${r.outcome === "failure" ? "fail" : "ok"}`}>{r.outcome === "failure" ? "ÉCHEC" : "RÉUSSIE"}</span>
                  <span className="wall-row-main">
                    <strong>{r.user || "—"}</strong>
                    <small>{SERVICE[r.service] ?? r.service}</small>
                  </span>
                  <span className="wall-row-ip">
                    {r.ip.startsWith("127.") ? <em>adresse masquée</em> : r.name ? <b className="wall-host">{r.name}</b> : r.ip}
                    <Country code={r.country} />
                  </span>
                  <span className="wall-row-time">{ago(r.ts)}</span>
                </div>
              ))}
            </AutoScroll>
          )}
        </section>
        <aside className="wall-side">
          <section className="wall-panel">
            <h2>Par service</h2>
            <div className="wall-bars">
              {vpn.services.map((x) => (
                <div key={x.service} className="wall-bar">
                  <span className="wall-bar-label">{SERVICE[x.service] ?? x.service}</span>
                  <span className="wall-bar-track">
                    <i className="fail" style={{ width: `${(x.failures / maxService) * 100}%` }} />
                    <i className="ok" style={{ width: `${(x.successes / maxService) * 100}%` }} />
                  </span>
                  <span className="wall-bar-values">
                    <b className="fail">{formatNumber(x.failures)}</b> / <b className="ok">{formatNumber(x.successes)}</b>
                  </span>
                </div>
              ))}
              <p className="wall-legend"><i className="fail" /> échecs <i className="ok" /> réussies</p>
            </div>
          </section>
          <section className="wall-panel">
            <h2>Comptes les plus visés</h2>
            <div className="wall-chips">
              {vpn.targeted.slice(0, 8).map((t) => (
                <span key={t.user} className="wall-chip">
                  {t.user}
                  <b>{t.failures}</b>
                </span>
              ))}
            </div>
          </section>
        </aside>
      </main>
    </>
  );
}

function AuthPage({ data }: { data: WallData }) {
  const maxFailures = Math.max(1, ...data.top_attackers.map((t) => t.failures));
  return (
    <main className="wall-main wall-auth">
      <section className="wall-panel">
        <h2>Échecs d'authentification · 24 h</h2>
        <HourlyBars points={data.auth_failures_hourly} />
        {data.failures_by_country?.length > 0 && (
          <>
            <h2 className="wall-sub">Origine des échecs</h2>
            <CountryBars rows={data.failures_by_country.slice(0, 6)} />
          </>
        )}
      </section>
      <section className="wall-panel">
        <h2>Adresses les plus actives en échec</h2>
        {data.top_attackers.length === 0 ? (
          <p className="wall-empty">Aucune</p>
        ) : (
          <AutoScroll className="wall-rows">
            {data.top_attackers.map((t) => (
              <div key={t.ip} className="wall-row wall-row-attacker">
                <span className="wall-row-main">
                  <strong className={t.name ? "" : "wall-mono"}>{t.name || t.ip}</strong>
                  {t.name && <small className="wall-mono">{t.ip}</small>}
                </span>
                <span className="wall-row-cc">
                  <Country code={t.country ?? ""} />
                </span>
                <span className="wall-row-users">
                  {t.users} compte{t.users > 1 ? "s" : ""}
                </span>
                <span className="wall-meter">
                  <i style={{ width: `${Math.max(3, (t.failures / maxFailures) * 100)}%` }} />
                </span>
                <span className="wall-row-count">{formatNumber(t.failures)}</span>
              </div>
            ))}
          </AutoScroll>
        )}
      </section>
    </main>
  );
}

function VulnPage({ v }: { v: NonNullable<WallData["vulnerabilities"]> }) {
  return (
    <>
      <section className="wall-kpis">
        <Kpi value={v.with_kev} label="Actifs avec faille KEV" tone={v.with_kev ? "critical" : "ok"} />
        <Kpi value={v.kev_cves} label="Failles KEV distinctes" tone={v.kev_cves ? "high" : "ok"} />
        <Kpi value={v.eol} label="Systèmes en fin de support" tone={v.eol ? "high" : "ok"} />
        <Kpi value={v.assets} label="Actifs suivis (Cyberwatch)" tone="neutral" />
      </section>
      <main className="wall-main wall-one">
        <section className="wall-panel">
          <h2>Actifs les plus exposés</h2>
          <AutoScroll className="wall-rows">
            {v.exposed.map((a) => (
              <div key={a.name} className="wall-row">
                <span className={`wall-pill ${a.kev ? "fail" : "warn"}`}>{a.kev ? `${a.kev} KEV` : "—"}</span>
                <span className="wall-row-main">
                  <strong>{a.name}</strong>
                  <small>
                    {a.server ? "serveur" : "poste"} · {a.os || "système inconnu"}
                    {a.eol_passed && <em className="wall-eol"> · fin de support</em>}
                  </small>
                </span>
                <span className="wall-row-count">
                  {formatNumber(a.prioritized)} <small>prioritaires</small>
                </span>
              </div>
            ))}
          </AutoScroll>
        </section>
      </main>
    </>
  );
}

function SourcesPage({ sources }: { sources: Source[] }) {
  return (
    <main className="wall-main wall-one">
      <section className="wall-panel">
        <h2>Sources en défaut</h2>
        <SilentSources sources={sources} big />
      </section>
    </main>
  );
}

/** Sources qui ne remontent plus rien depuis leur délai de surveillance ; si aucune, une ligne « tout va bien ». */
function SilentSources({ sources, big = false }: { sources: Source[]; big?: boolean }) {
  const silent = sources.filter((x) => x.status === "silent");
  if (silent.length === 0) {
    return (
      <p className="wall-sources-ok">
        <i /> Toutes les sources remontent ({sources.length})
      </p>
    );
  }
  return (
    <div className={`wall-sources ${big ? "wall-sources-big" : ""}`}>
      {silent.map((x) => (
        <div key={x.module} className="wall-source source-silent">
          <i />
          <span>{moduleLabel(x.module)}</span>
          <small>{x.last_seen ? `plus rien depuis ${timeAgo(x.last_seen).replace("il y a ", "")}` : "jamais reçue"}</small>
        </div>
      ))}
    </div>
  );
}

/** Liste qui défile lentement vers le haut quand elle dépasse son bloc : pause en haut, descente douce, pause en
 * bas, retour en haut. Une liste qui tient entière reste immobile. */
function AutoScroll({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [overflowing, setOverflowing] = useState(false);
  const overflowRef = useRef(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const SPEED = 22; // pixels par seconde
    const PAUSE_TOP = 4000;
    const PAUSE_BOTTOM = 3000;
    let raf = 0;
    let last = performance.now();
    let pos = 0;
    let phase: "wait" | "down" | "bottom" = "wait";
    let until = last + PAUSE_TOP;
    const step = (now: number) => {
      const dt = (now - last) / 1000;
      last = now;
      const max = el.scrollHeight - el.clientHeight;
      if (max > 4 !== overflowRef.current) {
        overflowRef.current = max > 4; // rendu seulement quand l'état change (pas à chaque image)
        setOverflowing(max > 4);
      }
      if (max <= 4) {
        pos = 0;
        el.scrollTop = 0;
        phase = "wait";
        until = now + PAUSE_TOP;
      } else if (now >= until) {
        if (phase === "wait") phase = "down";
        if (phase === "down") {
          pos = Math.min(max, pos + SPEED * dt);
          el.scrollTop = pos;
          if (pos >= max) {
            phase = "bottom";
            until = now + PAUSE_BOTTOM;
          }
        } else if (phase === "bottom") {
          pos = 0;
          el.scrollTo({ top: 0, behavior: "smooth" });
          phase = "wait";
          until = now + PAUSE_TOP;
        }
      }
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, []);
  return (
    <div ref={ref} className={`wall-autoscroll ${overflowing ? "is-overflowing" : ""} ${className}`}>
      {children}
    </div>
  );
}
