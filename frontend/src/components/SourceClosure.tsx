import { CircleCheck } from "lucide-react";
import { formatDate } from "../labels";
import type { SourceClosure } from "../types";

/** Outils dont le statut est synchronisé : une alerte traitée dans l'outil est clôturée dans le Mini-SOC. */
export const SYNCED_TOOLS = new Set(["harfanglab", "ninjaone"]);

/** Trace de la clôture constatée dans l'outil d'origine. */
export function SourceClosureNote({ closure }: { closure: SourceClosure }) {
  return (
    <div className="source-closure">
      <CircleCheck size={16} />
      <div>
        <strong>
          Clôturée dans {closure.tool} : {closure.label}
        </strong>
        <div className="small">
          {closure.by && <>par {closure.by} · </>}
          {closure.at && <>{closure.observed ? "constaté le " : "le "}{formatDate(closure.at)}</>}
          {closure.sources > 1 && <> · {closure.sources} alertes {closure.tool}, toutes traitées</>}
        </div>
        <div className="small muted">Clôture automatique par synchronisation : rien n'a été supprimé, l'historique est conservé.</div>
      </div>
    </div>
  );
}

/** Mention courte pour la liste des alertes. */
export function sourceClosureShort(closure: SourceClosure): string {
  return `dans ${closure.tool}${closure.by ? ` (${closure.by})` : ""}`;
}
