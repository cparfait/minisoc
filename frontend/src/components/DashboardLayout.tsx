import { Eye, EyeOff, GripVertical, RotateCcw, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";

/** Zones du tableau de bord : bandeau pleine largeur en haut, puis deux colonnes indépendantes. */
export type Zone = "top" | "left" | "right";

export interface WidgetSetting {
  id: string;
  zone: Zone;
  hidden: boolean;
  options: Record<string, number | string>;
}

export interface WidgetOption {
  key: string;
  label: string;
  values: { value: number | string; label: string }[];
  default: number | string;
}

export interface WidgetDef {
  id: string;
  title: string;
  description: string;
  zone: Zone;
  options?: WidgetOption[];
  /** Carte proposée mais masquée par défaut (à afficher depuis « Personnaliser »). */
  hidden?: boolean;
}

export interface Layout {
  version: 1;
  widgets: WidgetSetting[];
}

const ZONE_LABEL: Record<Zone, string> = { top: "En haut (pleine largeur)", left: "Colonne de gauche", right: "Colonne de droite" };

/** Disposition par défaut, complétée avec les cartes ajoutées depuis (une préférence ancienne reste valable). */
export function defaultLayout(defs: WidgetDef[]): Layout {
  return {
    version: 1,
    widgets: defs.map((d) => ({
      id: d.id,
      zone: d.zone,
      hidden: Boolean(d.hidden),
      options: Object.fromEntries((d.options ?? []).map((o) => [o.key, o.default])),
    })),
  };
}

export function mergeLayout(saved: Layout | null | undefined, defs: WidgetDef[]): Layout {
  const base = defaultLayout(defs);
  if (!saved?.widgets?.length) return base;
  const known = new Map(base.widgets.map((w) => [w.id, w]));
  const widgets: WidgetSetting[] = [];
  for (const w of saved.widgets) {
    const def = known.get(w.id);
    if (!def) continue; // carte retirée de l'application
    widgets.push({ ...def, ...w, options: { ...def.options, ...(w.options ?? {}) } });
    known.delete(w.id);
  }
  return { version: 1, widgets: [...widgets, ...known.values()] };
}

/** Disposition de l'utilisateur, lue et enregistrée côté serveur (préférence « dashboard »). */
export function useDashboardLayout(defs: WidgetDef[]) {
  const [layout, setLayout] = useState<Layout>(() => defaultLayout(defs));
  const [loaded, setLoaded] = useState(false);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    api<{ value: Layout | null }>("/auth/me/preferences/dashboard")
      .then((r) => setLayout(mergeLayout(r.value, defs)))
      .catch(() => undefined)
      .finally(() => setLoaded(true));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = useCallback((next: Layout | null) => {
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      api("/auth/me/preferences/dashboard", { method: "PUT", body: next ?? {} }).catch(() => undefined);
    }, 600);
  }, []);

  const update = useCallback(
    (next: Layout) => {
      setLayout(next);
      save(next);
    },
    [save],
  );
  const reset = useCallback(() => {
    setLayout(defaultLayout(defs));
    save(null);
  }, [defs, save]);

  return { layout, loaded, update, reset };
}

/** Panneau « Personnaliser » : glisser-déposer les cartes d'une zone à l'autre, afficher/masquer, réglages. */
export function DashboardCustomizer({
  defs,
  layout,
  onChange,
  onReset,
  onClose,
}: {
  defs: WidgetDef[];
  layout: Layout;
  onChange: (layout: Layout) => void;
  onReset: () => void;
  onClose: () => void;
}) {
  const byId = new Map(defs.map((d) => [d.id, d]));
  const [dragged, setDragged] = useState<string | null>(null);
  const [over, setOver] = useState<string | null>(null); // carte ou zone survolée (« zone:left »…)
  const patch = (id: string, change: Partial<WidgetSetting>) =>
    onChange({ ...layout, widgets: layout.widgets.map((w) => (w.id === id ? { ...w, ...change } : w)) });

  /** Déplace la carte `id` dans `zone`, avant la carte `beforeId` (ou en fin de zone). */
  const moveTo = (id: string, zone: Zone, beforeId: string | null) => {
    if (id === beforeId) return;
    const moving = layout.widgets.find((w) => w.id === id);
    if (!moving) return;
    const rest = layout.widgets.filter((w) => w.id !== id);
    let index = beforeId ? rest.findIndex((w) => w.id === beforeId) : -1;
    if (index < 0) {
      const lastInZone = rest.map((w) => w.zone).lastIndexOf(zone);
      index = lastInZone < 0 ? rest.length : lastInZone + 1;
    }
    rest.splice(index, 0, { ...moving, zone });
    onChange({ ...layout, widgets: rest });
  };
  const endDrag = () => {
    setDragged(null);
    setOver(null);
  };

  return (
    <section className="card customizer">
      <div className="customizer-head">
        <h2>Personnaliser le tableau de bord</h2>
        <span className="muted small">Glissez les cartes pour les déplacer. Enregistré automatiquement pour votre compte.</span>
        <span className="spacer" />
        <button type="button" onClick={onReset} title="Revenir à la disposition d'origine">
          <RotateCcw size={14} /> Réinitialiser
        </button>
        <button type="button" className="primary" onClick={onClose}>
          <X size={14} /> Terminer
        </button>
      </div>
      <div className="customizer-zones">
        {(["top", "left", "right"] as Zone[]).map((zone) => {
          const items = layout.widgets.filter((w) => w.zone === zone);
          return (
            <div
              key={zone}
              className={`customizer-zone ${over === `zone:${zone}` ? "drop-zone" : ""}`}
              onDragOver={(e) => {
                e.preventDefault();
                if (over !== `zone:${zone}` && !items.some((w) => w.id === over)) setOver(`zone:${zone}`);
              }}
              onDrop={(e) => {
                e.preventDefault();
                if (dragged) moveTo(dragged, zone, null);
                endDrag();
              }}
            >
              <h3>{ZONE_LABEL[zone]}</h3>
              {items.length === 0 && <p className="muted small drop-hint">Déposez une carte ici.</p>}
              {items.map((w) => {
                const def = byId.get(w.id);
                if (!def) return null;
                return (
                  <div
                    key={w.id}
                    draggable
                    className={`customizer-item ${w.hidden ? "is-hidden" : ""} ${dragged === w.id ? "is-dragged" : ""} ${over === w.id && dragged !== w.id ? "drop-before" : ""}`}
                    onDragStart={(e) => {
                      e.dataTransfer.effectAllowed = "move";
                      e.dataTransfer.setData("text/plain", w.id);
                      setDragged(w.id);
                    }}
                    onDragEnd={endDrag}
                    onDragOver={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      if (over !== w.id) setOver(w.id);
                    }}
                    onDrop={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      if (dragged) moveTo(dragged, zone, w.id);
                      endDrag();
                    }}
                  >
                    <div className="customizer-row">
                      <GripVertical size={15} className="grip" aria-hidden />
                      <strong title={def.description}>{def.title}</strong>
                      <span className="spacer" />
                      {(def.options ?? []).map((o) => (
                        <label key={o.key} className="inline small">
                          {o.label}
                          <select
                            value={String(w.options[o.key] ?? o.default)}
                            onChange={(e) => {
                              const raw = o.values.find((v) => String(v.value) === e.target.value)?.value ?? o.default;
                              patch(w.id, { options: { ...w.options, [o.key]: raw } });
                            }}
                          >
                            {o.values.map((v) => (
                              <option key={String(v.value)} value={String(v.value)}>{v.label}</option>
                            ))}
                          </select>
                        </label>
                      ))}
                      <button type="button" className="icon-button" title={w.hidden ? "Afficher" : "Masquer"} onClick={() => patch(w.id, { hidden: !w.hidden })}>
                        {w.hidden ? <EyeOff size={15} /> : <Eye size={15} />}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          );
        })}
      </div>
    </section>
  );
}
