import { useEffect, useState } from "react";
import { api } from "./api";

/**
 * Passage de la liste des alertes à leur détail, et retour : filtres, position dans la liste, alerte suivante ou
 * précédente. Mémorisé pour l'onglet (sessionStorage) : le détail ouvert depuis un autre écran ne propose que le retour.
 */
export interface AlertList {
  search: string; // filtres de la liste, tels que dans son adresse
  apiQuery: string; // même requête côté API, sans limit ni offset
  ids: number[]; // alertes connues, dans l'ordre de la liste
  offset: number; // rang de ids[0] dans la liste complète
  total: number;
  pageSize: number;
}

const LIST_KEY = "minisoc.alerts.list";
const RETURN_KEY = "minisoc.alerts.return";

function read<T>(key: string): T | null {
  try {
    return JSON.parse(sessionStorage.getItem(key) ?? "null") as T | null;
  } catch {
    return null;
  }
}

export const saveAlertList = (list: AlertList) => sessionStorage.setItem(LIST_KEY, JSON.stringify(list));
const readAlertList = () => read<AlertList>(LIST_KEY);

/** Point de retour dans la liste : dernière alerte consultée, et défilement si elle en est sortie (clôturée…). */
export interface AlertReturn {
  id: number;
  y?: number;
  search?: string;
}

export function markAlertOpened(id: number, search: string) {
  sessionStorage.setItem(RETURN_KEY, JSON.stringify({ id, y: window.scrollY, search } satisfies AlertReturn));
}

/** Lu une seule fois pour le défilement ; l'identifiant reste pour repérer la ligne dans la liste. */
export function takeAlertReturn(): AlertReturn | null {
  const value = read<AlertReturn>(RETURN_KEY);
  if (value) sessionStorage.setItem(RETURN_KEY, JSON.stringify({ id: value.id }));
  return value;
}

export const lastViewedAlert = () => read<AlertReturn>(RETURN_KEY)?.id ?? null;

export interface AlertNeighbours {
  backTo: string;
  position: number | null; // rang de l'alerte dans la liste (à partir de 1), si elle y figure
  total: number;
  prev: number | null;
  next: number | null;
}

/** Voisines de l'alerte dans la liste d'où l'on vient ; la page voisine est chargée en arrivant au bord de la page. */
export function useAlertNeighbours(id: number): AlertNeighbours {
  const [list, setList] = useState<AlertList | null>(readAlertList);
  const index = list ? list.ids.indexOf(id) : -1;

  useEffect(() => {
    if (!list || index < 0) return;
    const stored = read<AlertReturn>(RETURN_KEY);
    sessionStorage.setItem(RETURN_KEY, JSON.stringify({ ...stored, id }));
    const atEnd = index === list.ids.length - 1 && list.offset + list.ids.length < list.total;
    const atStart = index === 0 && list.offset > 0;
    if (!atEnd && !atStart) return;
    let alive = true;
    const offset = atEnd ? list.offset + list.ids.length : Math.max(0, list.offset - list.pageSize);
    api<{ total: number; items: { id: number }[] }>(`/alerts${list.apiQuery}${list.apiQuery ? "&" : "?"}limit=${list.pageSize}&offset=${offset}`)
      .then((r) => {
        if (!alive) return;
        const known = new Set(list.ids);
        const fresh = r.items.map((a) => a.id).filter((x) => !known.has(x));
        // Rien de nouveau (la liste a bougé) : on s'arrête à ce bord
        const next: AlertList = atEnd
          ? { ...list, ids: [...list.ids, ...fresh], total: fresh.length ? r.total : list.offset + list.ids.length }
          : { ...list, ids: [...fresh, ...list.ids], offset: fresh.length ? Math.max(0, list.offset - fresh.length) : 0 };
        saveAlertList(next);
        setList(next);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [id, index, list]);

  if (!list) return { backTo: "/alerts", position: null, total: 0, prev: null, next: null };
  if (index < 0) return { backTo: `/alerts${list.search}`, position: null, total: 0, prev: null, next: null };
  // Retour sur la page de la liste où se trouve l'alerte consultée (après être passé d'une page à l'autre)
  const params = new URLSearchParams(list.search);
  const page = Math.floor((list.offset + index) / list.pageSize) + 1;
  if (page > 1) params.set("page", String(page));
  else params.delete("page");
  const search = params.toString();
  return {
    backTo: `/alerts${search ? `?${search}` : ""}`,
    position: list.offset + index + 1,
    total: list.total,
    prev: index > 0 ? list.ids[index - 1] : null,
    next: index < list.ids.length - 1 ? list.ids[index + 1] : null,
  };
}
