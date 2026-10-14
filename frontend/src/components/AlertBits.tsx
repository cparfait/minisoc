import type { CSSProperties } from "react";
import { moduleLabel } from "../labels";
import type { Alert } from "../types";

/** Couleur de chaque outil (badge « Outil » de la liste des alertes). */
const TOOL_COLOR: Record<string, string> = {
  harfanglab: "#a855f7",
  sophos_xgs: "#3b82f6",
  bitdefender: "#ef4444",
  m365: "#0ea5e9",
  windows: "#14b8a6",
  vectra: "#ec4899",
  varonis: "#f59e0b",
  crowdsec: "#f97316",
  ninjaone: "#22c55e",
  cyberwatch: "#84cc16",
  ogo: "#6366f1",
};

/** Palette des noms de détection : une même détection garde toujours la même couleur. */
const NAME_PALETTE = ["#60a5fa", "#f472b6", "#34d399", "#fbbf24", "#a78bfa", "#f87171", "#22d3ee", "#fb923c", "#a3e635", "#e879f9"];

function hash(text: string): number {
  let h = 0;
  for (let i = 0; i < text.length; i++) h = (h * 31 + text.charCodeAt(i)) | 0;
  return Math.abs(h);
}

export function ToolBadge({ module }: { module?: string }) {
  const label = module ? moduleLabel(module) : "Mini-SOC";
  const color = (module && TOOL_COLOR[module]) || "#94a3b8";
  return (
    <span className="tool-badge" style={{ "--tool": color } as CSSProperties} title={label}>
      {label}
    </span>
  );
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Nom de la détection, sans l'outil ni la machine (affichés dans leurs colonnes). */
export function detectionName(alert: Alert): string {
  let name = alert.title;
  for (const m of alert.modules) {
    name = name.replace(new RegExp(`^(${escape(m)}|${escape(moduleLabel(m))})\\s*:\\s*`, "i"), "");
  }
  for (const h of alert.hosts ?? []) {
    name = name.replace(new RegExp(`\\s*\\(${escape(h.name)}\\)$`, "i"), "");
  }
  return name || alert.title;
}

export function DetectionName({ name }: { name: string }) {
  const color = NAME_PALETTE[hash(name.toLowerCase()) % NAME_PALETTE.length];
  return (
    <span className="detection-name" style={{ "--name": color } as CSSProperties}>
      <i aria-hidden />
      {name}
    </span>
  );
}

const HIDDEN_PARTS = new Set(["event.module", "host.name", "rule.name"]);

/** Clé d'entité sans les éléments déjà visibles (outil, machine, nom de la détection). */
export function residualEntity(entityKey: string): string {
  return entityKey
    .split(" | ")
    .filter((part) => !HIDDEN_PARTS.has(part.split("=")[0].trim()))
    .join(" | ");
}
