import { Lightbulb, SlidersHorizontal, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { usePolling } from "../hooks";
import { SEVERITY_LABEL, formatNumber, timeAgo } from "../labels";
import type { DetectionCategory, DetectionTopic, Severity } from "../types";
import { DetectionName, ToolBadge } from "./AlertBits";
import { HostChips } from "./Hosts";
import { CATEGORY_LABEL, CategoryBadge } from "./Priority";
import { Empty, ErrorBanner, SeverityBadge } from "./ui";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const CATEGORY_HELP: Record<DetectionCategory, string> = {
  threat: "Signe possible d'attaque : à traiter en priorité.",
  hygiene: "Faiblesse du parc (pilote vulnérable, logiciel obsolète…) : à corriger, mais pas une attaque en cours.",
  info: "Activité connue et attendue : gardée pour mémoire, sans urgence.",
};

interface Draft {
  category: DetectionCategory;
  severity: Severity | "";
  note: string;
  apply_open: boolean;
}

function Editor({ topic, onDone }: { topic: DetectionTopic; onDone: () => void }) {
  const initial: Draft = topic.profile
    ? { category: topic.profile.category, severity: topic.profile.severity ?? "", note: topic.profile.note, apply_open: true }
    : { category: "threat", severity: "", note: "", apply_open: true };
  const [draft, setDraft] = useState<Draft>(initial);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const save = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const res = await api<{ reset: boolean; open_alerts_changed: number }>("/detections/profile", {
        method: "PUT",
        body: { module: topic.module, detection: topic.detection, ...draft, severity: draft.severity || null },
      });
      setMessage({
        ok: true,
        text: `${res.reset ? "Fiche retirée" : "Fiche enregistrée"} : ${res.open_alerts_changed} alerte(s) ouverte(s) mise(s) à jour.`,
      });
      onDone();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="topic-editor">
      {topic.suggestion && (
        <div className="topic-suggestion">
          <Lightbulb size={16} />
          <div>
            <strong>
              Suggestion : {CATEGORY_LABEL[topic.suggestion.category]}
              {topic.suggestion.severity && `, sévérité ${SEVERITY_LABEL[topic.suggestion.severity].toLowerCase()}`}
            </strong>
            <p className="small">{topic.suggestion.why}</p>
            <button
              type="button"
              className="link"
              onClick={() =>
                setDraft({ ...draft, category: topic.suggestion!.category, severity: topic.suggestion!.severity ?? "", note: topic.suggestion!.why })
              }
            >
              Reprendre la suggestion
            </button>
          </div>
        </div>
      )}
      <div className="topic-editor-grid">
        <fieldset>
          <legend>Catégorie</legend>
          {(Object.keys(CATEGORY_LABEL) as DetectionCategory[]).map((c) => (
            <label key={c} className="radio">
              <input type="radio" name={`cat-${topic.detection}`} checked={draft.category === c} onChange={() => setDraft({ ...draft, category: c })} />
              <span>
                <strong>{CATEGORY_LABEL[c]}</strong>
                <small className="muted">{CATEGORY_HELP[c]}</small>
              </span>
            </label>
          ))}
        </fieldset>
        <div className="stack">
          <label>
            Sévérité retenue
            <select value={draft.severity} onChange={(e) => setDraft({ ...draft, severity: e.target.value as Severity | "" })}>
              <option value="">Celle de l'outil ({topic.tool_severity ? SEVERITY_LABEL[topic.tool_severity].toLowerCase() : "?"})</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABEL[s]}
                </option>
              ))}
            </select>
          </label>
          <label>
            Justification (visible dans l'historique et le journal d'audit)
            <textarea rows={3} value={draft.note} onChange={(e) => setDraft({ ...draft, note: e.target.value })} />
          </label>
          <label className="checkbox">
            <input type="checkbox" checked={draft.apply_open} onChange={(e) => setDraft({ ...draft, apply_open: e.target.checked })} />
            Appliquer aussi aux {formatNumber(topic.alerts)} alerte(s) ouverte(s) de cette détection
          </label>
          <div className="row">
            <button type="button" className="primary" disabled={busy} onClick={save}>
              {busy ? "Enregistrement…" : "Enregistrer la fiche"}
            </button>
            {message && <span className={message.ok ? "text-good" : "form-error"}>{message.text}</span>}
          </div>
          <p className="muted small">
            S'applique aussi aux prochaines alertes de cette détection. « Menace » avec la sévérité de l'outil et sans justification
            retire la fiche.
          </p>
        </div>
      </div>
    </div>
  );
}

/** Alertes ouvertes regroupées par détection d'outil, avec la qualification (fiche) de chaque détection. */
export default function DetectionTopics({ editable }: { editable: boolean }) {
  const { data, error, reload } = usePolling(() => api<{ items: DetectionTopic[] }>("/detections"), [], 30000);
  const [category, setCategory] = useState<DetectionCategory | "">("");
  const [open, setOpen] = useState<string | null>(null);
  const items = (data?.items ?? []).filter((t) => !category || t.category === category);
  const count = (c: DetectionCategory) => data?.items.filter((t) => t.category === c).length ?? 0;
  const keyOf = (t: DetectionTopic) => `${t.module}|${t.detection}`;
  const editing = data?.items.find((t) => keyOf(t) === open);
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (open) panel.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [open]);

  return (
    <>
      <ErrorBanner error={error} />
      <div className="filters">
        <div className="segmented" role="group" aria-label="Catégorie">
          <button className={category === "" ? "active" : ""} onClick={() => setCategory("")}>
            Toutes<span className="count">{data?.items.length ?? 0}</span>
          </button>
          {(Object.keys(CATEGORY_LABEL) as DetectionCategory[]).map((c) => (
            <button key={c} className={category === c ? "active" : ""} onClick={() => setCategory(c)}>
              {CATEGORY_LABEL[c]}
              <span className="count">{count(c)}</span>
            </button>
          ))}
        </div>
        <span className="muted small">Une ligne par détection d'outil, toutes machines confondues (alertes ouvertes).</span>
      </div>
      {editing && (
        <div className="topic-panel" ref={panel}>
          <div className="topic-panel-head">
            <ToolBadge module={editing.module} />
            <strong>Qualifier la détection « {editing.detection} »</strong>
            <span className="muted small">
              {editing.machines} machine(s), {editing.alerts} alerte(s) ouverte(s)
            </span>
            <button type="button" className="icon-button" aria-label="Fermer" onClick={() => setOpen(null)}>
              <X size={16} />
            </button>
          </div>
          <Editor key={open ?? ""} topic={editing} onDone={reload} />
        </div>
      )}
      {data && items.length === 0 ? (
        <Empty>Aucune détection dans cette catégorie.</Empty>
      ) : (
        <div className="table-scroll">
          <table className="alerts-table topics-table">
            <thead>
              <tr>
                <th>Outil</th>
                <th>Détection</th>
                <th>Sévérité</th>
                <th>Machines</th>
                <th className="num">Alertes</th>
                <th className="num">Occurrences</th>
                <th>Activité</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {items.map((t) => {
                const key = keyOf(t);
                return (
                    <tr key={key} className={open === key ? "selected" : ""}>
                      <td className="tool-cell">
                        <ToolBadge module={t.module} />
                      </td>
                      <td className="alert-cell">
                        <Link to={`/alerts?detection=${encodeURIComponent(t.detection)}&module=${encodeURIComponent(t.module)}`}>
                          <DetectionName name={t.detection} />
                        </Link>{" "}
                        <CategoryBadge category={t.category} />
                        {t.suggestion && !t.profile && (
                          <span className="suggestion-hint" title={t.suggestion.why}>
                            <Lightbulb size={12} /> suggestion
                          </span>
                        )}
                        {t.widespread && <div className="muted small">Répandue : {t.machines} machines, plutôt un sujet de parc</div>}
                        {t.profile?.note && <div className="muted small alert-meta" title={t.profile.note}>{t.profile.note}</div>}
                      </td>
                      <td className="nowrap">
                        {t.severity && <SeverityBadge severity={t.severity} />}
                        {t.tool_severity && t.severity !== t.tool_severity && (
                          <div className="muted small">outil : {SEVERITY_LABEL[t.tool_severity].toLowerCase()}</div>
                        )}
                      </td>
                      <td className="hosts-cell">
                        <HostChips hosts={t.hosts} />
                        {t.servers > 0 && <div className="small text-warn">{t.servers} serveur(s)</div>}
                      </td>
                      <td className="num">
                        <Link to={`/alerts?detection=${encodeURIComponent(t.detection)}&module=${encodeURIComponent(t.module)}`}>
                          {formatNumber(t.alerts)}
                        </Link>
                      </td>
                      <td className="num">{formatNumber(t.occurrences)}</td>
                      <td className="nowrap">{t.last_seen ? timeAgo(t.last_seen) : "—"}</td>
                      <td>
                        {editable && (
                          <button type="button" className="ghost small icon-only" title="Qualifier cette détection (catégorie, sévérité)"
                            aria-label="Qualifier" onClick={() => setOpen(open === key ? null : key)}>
                            <SlidersHorizontal size={15} />
                          </button>
                        )}
                      </td>
                    </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
