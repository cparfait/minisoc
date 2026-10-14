import { Eye, EyeOff, GripVertical, MonitorPlay } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../api";

const PAGES: { id: string; label: string; description: string }[] = [
  { id: "alertes", label: "Alertes", description: "Compteurs, alertes hautes et critiques, sources, échecs (obligatoire)." },
  { id: "vpn", label: "Accès VPN", description: "Échecs et connexions depuis l'étranger, comptes visés." },
  { id: "auth", label: "Authentifications", description: "Courbe sur 24 h, pays d'origine, adresses en échec." },
  { id: "vuln", label: "Vulnérabilités", description: "Failles KEV présentes, fin de support (Cyberwatch)." },
  { id: "sources", label: "Sources", description: "État de chaque source en grand." },
];

interface Values {
  wall_pages: string[];
  wall_rotation: number;
  wall_flash_min_severity: string;
  wall_sound_default: boolean;
}

/** Paramètres › Écran mural : réglages communs à tous les écrans (ordre et choix des écrans, durée, alertes, son). */
export default function WallSettings() {
  const [values, setValues] = useState<Values | null>(null);
  const [order, setOrder] = useState<{ id: string; on: boolean }[]>([]);
  const [dragged, setDragged] = useState<string | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    api<{ values: Values }>("/admin/settings/wall").then((r) => {
      setValues(r.values);
      const enabled = r.values.wall_pages ?? [];
      setOrder([
        ...enabled.map((id) => ({ id, on: true })),
        ...PAGES.filter((p) => !enabled.includes(p.id)).map((p) => ({ id: p.id, on: false })),
      ]);
    });
  }, []);

  if (!values) return <p className="muted">Chargement…</p>;

  const drop = (targetId: string) => {
    if (!dragged || dragged === targetId) return;
    const moving = order.find((o) => o.id === dragged);
    if (!moving) return;
    const rest = order.filter((o) => o.id !== dragged);
    rest.splice(rest.findIndex((o) => o.id === targetId), 0, moving);
    setOrder(rest);
    setDragged(null);
  };

  const save = async () => {
    setMessage(null);
    try {
      await api("/admin/settings/wall", {
        method: "PUT",
        body: {
          wall_pages: order.filter((o) => o.on).map((o) => o.id),
          wall_rotation: values.wall_rotation,
          wall_flash_min_severity: values.wall_flash_min_severity,
          wall_sound_default: values.wall_sound_default,
        },
      });
      setMessage({ ok: true, text: "Enregistré : les écrans appliquent ces réglages à leur prochain rafraîchissement (15 s)." });
    } catch (e) {
      setMessage({ ok: false, text: e instanceof Error ? e.message : String(e) });
    }
  };

  return (
    <div className="wall-settings">
      <p className="muted">
        Réglages communs à tous les écrans muraux (jetons d'affichage). Un écran peut imposer sa propre durée par son adresse :{" "}
        <code>/wall#token=…&amp;rotation=30</code>. Le son se coupe ou s'active aussi directement sur l'écran.
      </p>
      <h3>Écrans qui défilent (glissez pour changer l'ordre)</h3>
      <div className="wall-settings-pages">
        {order.map((o) => {
          const page = PAGES.find((p) => p.id === o.id);
          if (!page) return null;
          return (
            <div
              key={o.id}
              draggable
              className={`customizer-item ${o.on ? "" : "is-hidden"} ${dragged === o.id ? "is-dragged" : ""}`}
              onDragStart={() => setDragged(o.id)}
              onDragEnd={() => setDragged(null)}
              onDragOver={(e) => e.preventDefault()}
              onDrop={() => drop(o.id)}
            >
              <div className="customizer-row">
                <GripVertical size={15} className="grip" aria-hidden />
                <strong>{page.label}</strong>
                <span className="muted small">{page.description}</span>
                <span className="spacer" />
                <button
                  type="button"
                  className="icon-button"
                  disabled={o.id === "alertes"}
                  title={o.id === "alertes" ? "Toujours affiché" : o.on ? "Ne pas afficher" : "Afficher"}
                  onClick={() => setOrder(order.map((x) => (x.id === o.id ? { ...x, on: !x.on } : x)))}
                >
                  {o.on ? <Eye size={15} /> : <EyeOff size={15} />}
                </button>
              </div>
            </div>
          );
        })}
      </div>
      <div className="settings-grid">
        <label>
          Durée d'affichage de chaque écran
          <select value={values.wall_rotation} onChange={(e) => setValues({ ...values, wall_rotation: Number(e.target.value) })}>
            {[10, 15, 20, 30, 45, 60, 120].map((n) => (
              <option key={n} value={n}>{n} secondes</option>
            ))}
            <option value={0}>Pas de défilement (écran « Alertes » seul)</option>
          </select>
        </label>
        <label>
          Afficher immédiatement en plein écran les nouvelles alertes
          <select value={values.wall_flash_min_severity} onChange={(e) => setValues({ ...values, wall_flash_min_severity: e.target.value })}>
            <option value="critical">critiques seulement</option>
            <option value="high">hautes et critiques</option>
            <option value="medium">moyennes, hautes et critiques</option>
          </select>
        </label>
        <label className="inline">
          <input type="checkbox" checked={values.wall_sound_default} onChange={(e) => setValues({ ...values, wall_sound_default: e.target.checked })} />
          Son discret activé par défaut (chaque écran peut le couper)
        </label>
      </div>
      <div className="wall-settings-actions">
        <button type="button" className="primary" onClick={save}>Enregistrer</button>
        <a className="button" href="/wall" target="_blank" rel="noopener noreferrer">
          <MonitorPlay size={15} /> Ouvrir l'écran mural
        </a>
      </div>
      {message && <p className={message.ok ? "text-good" : "text-bad"}>{message.text}</p>}
    </div>
  );
}
