import { CalendarClock, ExternalLink, Eye, Hand } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../api";
import { formatDate, moduleLabel, timeAgo } from "../labels";
import type { Alert } from "../types";

export const WAITING_REASONS: { value: string; label: string }[] = [
  { value: "utilisateur", label: "Réponse de l'utilisateur" },
  { value: "prestataire", label: "Intervention d'un prestataire" },
  { value: "editeur", label: "Réponse de l'éditeur" },
  { value: "correctif", label: "Correctif planifié" },
  { value: "autre", label: "Autre" },
];
export const waitingLabel = (reason?: string) => WAITING_REASONS.find((w) => w.value === reason)?.label ?? reason ?? "";

export interface Assignee {
  username: string;
  display_name: string;
  has_email: boolean;
}

/** Analystes et administrateurs à qui assigner une alerte (chargés une fois). */
export function useAssignees(): Assignee[] {
  const [items, setItems] = useState<Assignee[]>([]);
  useEffect(() => {
    api<{ items: Assignee[] }>("/alerts/assignees").then((r) => setItems(r.items)).catch(() => setItems([]));
  }, []);
  return items;
}

/** Retard sur l'échéance (prise en charge ou traitement). */
export function OverdueBadge({ alert }: { alert: Alert }) {
  if (!alert.due?.overdue) return null;
  const late = alert.due.overdue === "ack";
  const due = late ? alert.due.ack_due : alert.due.resolve_due;
  return (
    <span className="overdue-badge" title={`Échéance de ${late ? "prise en charge" : "traitement"} : ${formatDate(due)}`}>
      <CalendarClock size={11} /> {late ? "à prendre en charge" : "en retard"}
    </span>
  );
}

/** État lu dans l'outil d'origine (lecture seule). */
export function ToolStateLine({ alert }: { alert: Alert }) {
  const s = alert.tool_state;
  if (!s || alert.source_closure) return null;
  return (
    <div className={`tool-state small ${s.status === "investigating" ? "investigating" : ""}`} title={`Lu dans ${s.tool}${s.checked_at ? ` ${timeAgo(s.checked_at)}` : ""}`}>
      <Eye size={11} /> {s.tool} : {s.label}
      {s.by && ` (${s.by})`}
    </div>
  );
}

const SYNCED = new Set(["harfanglab", "ninjaone"]);
const CALCULATED = new Set(["UC-42", "UC-43", "UC-44", "UC-45"]);

/** Marche à suivre pour agir dans l'outil d'origine : le Mini-SOC ne modifie pas les outils. */
const STEPS: Record<string, string[]> = {
  harfanglab: [
    "Ouvrir l'alerte dans la console HarfangLab (bouton ci-dessous).",
    "Prendre en charge : passer son statut à « En investigation » ; le Mini-SOC l'affiche ici sous 5 minutes.",
    "Si c'est malveillant : isoler le poste depuis la fiche de l'agent (Isolation), analyser (processus, fichiers, connexions), puis passer l'alerte en « Clôturée ».",
    "Si c'est légitime : statut « Faux positif » ; pour qu'elle ne revienne pas, créer une exclusion (liste blanche) limitée au strict nécessaire : chemin du programme, signataire, machine.",
    "Le Mini-SOC clôture automatiquement son alerte quand toutes les alertes HarfangLab d'origine sont traitées, en gardant la trace.",
  ],
  ninjaone: [
    "Ouvrir l'appareil dans NinjaOne (bouton ci-dessous).",
    "Corriger la cause : réactiver ou mettre à jour l'antivirus, installer les correctifs, traiter la menace signalée.",
    "Réinitialiser l'alerte (Reset) dans NinjaOne ; pour un problème de posture, le relevé suivant constate la résolution.",
    "Le Mini-SOC clôture automatiquement son alerte, en gardant la trace.",
  ],
  sophos_xgs: [
    "Ouvrir la console du Sophos XGS : Journaux et rapports › Visionneuse de journaux (filtrer sur l'adresse IP ou le compte).",
    "Pour bloquer une adresse : ajouter l'IP au groupe d'hôtes de blocage (règle de pare-feu et exception d'accès au VPN), avec une date de fin.",
    "Compte VPN visé : vérifier avec l'utilisateur, réinitialiser son mot de passe, imposer la double authentification.",
    "Le pare-feu ne gère pas d'état d'alerte : clôturer ici une fois traité.",
  ],
  bitdefender: [
    "Ouvrir la console GravityZone (bouton ci-dessous) : Incidents ou Rapports, filtrer sur la machine.",
    "Lancer une analyse complète, isoler le poste si la menace n'est pas neutralisée.",
    "Clôturer ici une fois traité (pas de synchronisation de statut avec GravityZone).",
  ],
  windows: [
    "Vérifier l'action dans l'annuaire (Utilisateurs et ordinateurs Active Directory, ou journaux du contrôleur).",
    "Compte suspect : le désactiver ou réinitialiser son mot de passe ; groupe à privilèges : retirer l'ajout non prévu.",
    "Clôturer ici une fois traité.",
  ],
  m365: [
    "Ouvrir le centre d'administration Microsoft Entra : Utilisateurs › compte concerné › Journaux de connexion.",
    "Connexion non légitime : révoquer les sessions, réinitialiser le mot de passe, vérifier les règles de transfert de la messagerie et les applications autorisées.",
    "Clôturer ici une fois traité.",
  ],
};

export function ToolActions({ alert }: { alert: Alert }) {
  const module = alert.modules[0] ?? "";
  if (CALCULATED.has(alert.rule_id) || !module) {
    return (
      <div className="tool-actions">
        <h3><Hand size={15} /> Où traiter cette alerte</h3>
        <p className="small">
          Alerte <strong>calculée par le Mini-SOC</strong> (règle {alert.rule_id}) : elle n'existe dans aucun outil, elle se traite et se
          clôture ici. Les alertes d'outils qu'elle cite se traitent chacune dans leur outil.
        </p>
      </div>
    );
  }
  const steps = STEPS[module] ?? [
    `Ouvrir la console ${moduleLabel(module)} et vérifier l'événement (bouton ci-dessous s'il est disponible).`,
    "Agir dans l'outil si nécessaire (blocage, exclusion, correction).",
    "Clôturer ici une fois traité (pas de synchronisation de statut avec cet outil).",
  ];
  return (
    <div className="tool-actions">
      <h3><Hand size={15} /> Agir dans {moduleLabel(module)}</h3>
      <p className="muted small">
        Le Mini-SOC lit les outils sans jamais les modifier.{" "}
        {SYNCED.has(module)
          ? "Une fois l'alerte traitée dans l'outil, elle se clôture ici automatiquement."
          : "Cet outil ne transmet pas d'état : clôturez l'alerte ici une fois traitée."}
      </p>
      <ol className="small">
        {steps.map((s) => <li key={s}>{s}</li>)}
      </ol>
      {alert.reference && (
        <a className="button" href={alert.reference} target="_blank" rel="noopener noreferrer">
          Ouvrir dans {moduleLabel(module)} <ExternalLink size={14} />
        </a>
      )}
    </div>
  );
}
