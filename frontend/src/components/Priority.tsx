import type { DetectionCategory, PriorityReason } from "../types";

export const CATEGORY_LABEL: Record<DetectionCategory, string> = {
  threat: "Menace",
  hygiene: "Hygiène du parc",
  info: "Information",
};

const level = (score: number) => (score >= 75 ? "p-high" : score >= 50 ? "p-mid" : score >= 30 ? "p-low" : "p-min");

/** Score de priorité (0-100), raisons au survol. */
export function PriorityPill({ score, reasons = [] }: { score?: number; reasons?: PriorityReason[] }) {
  if (score === undefined) return null;
  const title = reasons.map((r) => `${r.points > 0 ? "+" : ""}${r.points}  ${r.label}`).join("\n");
  return (
    <span className={`priority-pill ${level(score)}`} title={`Priorité ${score}/100\n${title}`}>
      {score}
    </span>
  );
}

/** Détail des raisons (fiche d'alerte). */
export function PriorityReasons({ reasons }: { reasons: PriorityReason[] }) {
  return (
    <ul className="priority-reasons">
      {reasons.map((r) => (
        <li key={r.label} className={r.points >= 0 ? "plus" : "minus"}>
          <span className="pts">{r.points > 0 ? "+" : ""}{r.points}</span> {r.label}
        </li>
      ))}
    </ul>
  );
}

/** Badge de catégorie, affiché seulement hors « menace » (la valeur par défaut). */
export function CategoryBadge({ category }: { category?: DetectionCategory | null }) {
  if (!category || category === "threat") return null;
  return <span className={`category-badge cat-${category}`}>{CATEGORY_LABEL[category]}</span>;
}
