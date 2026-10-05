/** Thème clair / sombre : choix mémorisé dans le navigateur (sombre par défaut, adapté à un poste de supervision). */

export type Theme = "dark" | "light";
const KEY = "minisoc-theme";

export function storedTheme(): Theme {
  try {
    return localStorage.getItem(KEY) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // stockage indisponible (navigation privée) : le thème vaut pour la session
  }
}

export function applyStoredTheme(): void {
  document.documentElement.dataset.theme = storedTheme();
}
