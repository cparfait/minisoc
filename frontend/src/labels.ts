import type { AlertStatus, Severity } from "./types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critique",
  high: "Haute",
  medium: "Moyenne",
  low: "Faible",
  info: "Info",
};

export const STATUS_LABEL: Record<AlertStatus, string> = {
  new: "Nouvelle",
  in_progress: "En cours",
  waiting: "En attente",
  resolved: "Résolue",
  false_positive: "Faux positif",
};

export const MODULE_LABEL: Record<string, string> = {
  sophos_xgs: "Sophos XGS",
  bitdefender: "Bitdefender",
  harfanglab: "HarfangLab",
  m365: "Microsoft 365",
  windows: "Windows / AD",
  vectra: "Vectra",
  varonis: "Varonis",
  crowdsec: "CrowdSec",
  ninjaone: "NinjaOne",
  cyberwatch: "Cyberwatch",
  ogo: "OGO Security",
  syslog: "Syslog générique",
  unparsed: "Non analysé",
};

export const ACTION_LABEL: Record<string, string> = {
  created: "Création",
  escalated: "Sévérité relevée",
  status: "Statut",
  assign: "Assignation",
  comment: "Commentaire",
  notified: "Notification",
  reminder: "Relance (non prise en charge)",
};

export const moduleLabel = (m: string) => MODULE_LABEL[m] ?? m;

const dateFormat = new Intl.DateTimeFormat("fr-FR", {
  dateStyle: "short",
  timeStyle: "medium",
  timeZone: "Europe/Paris",
});

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : dateFormat.format(date);
}

export function timeAgo(value: string | null | undefined): string {
  if (!value) return "jamais";
  const seconds = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  if (seconds < 60) return "à l'instant";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `il y a ${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `il y a ${hours} h`;
  return `il y a ${Math.round(hours / 24)} j`;
}

export const formatNumber = (n: number) => new Intl.NumberFormat("fr-FR").format(n);

const shortFormat = new Intl.DateTimeFormat("fr-FR", {
  day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", timeZone: "Europe/Paris",
});

/** Date courte pour les tableaux : « 02/10 13:34 ». */
export function formatShort(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : shortFormat.format(date).replace(",", "");
}
