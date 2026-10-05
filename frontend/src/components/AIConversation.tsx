import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, streamAI, type AIEvent } from "../api";
import Markdown from "./Markdown";

interface Turn {
  role: "user" | "assistant";
  content: string;
}
interface Status {
  enabled: boolean;
  provider: string;
  model: string;
  pseudonymize: boolean;
  local: boolean;
}

/**
 * Conversation avec l'assistant IA. `path` = point d'API ; `initialQuestion` lance l'analyse sans saisie
 * (analyse d'alerte). L'historique est renvoyé à chaque tour ; le serveur reconstruit le contexte.
 */
export default function AIConversation({ path, initialQuestion, placeholder, autoStart = false }: {
  path: string;
  initialQuestion?: string;
  placeholder: string;
  autoStart?: boolean;
}) {
  const [status, setStatus] = useState<Status | null>(null);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [notices, setNotices] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [meta, setMeta] = useState<string>("");
  const abort = useRef<AbortController | null>(null);
  const started = useRef(false);

  useEffect(() => {
    api<Status>("/ai/status").then(setStatus).catch(() => setStatus(null));
    return () => abort.current?.abort();
  }, []);

  const ask = async (question: string, history: Turn[]) => {
    const next: Turn[] = [...history, { role: "user", content: question }];
    setTurns([...next, { role: "assistant", content: "" }]);
    setBusy(true);
    setError(null);
    setNotices([]);
    abort.current = new AbortController();
    let answer = "";
    try {
      await streamAI(path, { messages: next }, (e: AIEvent) => {
        if (e.type === "text") {
          answer += e.text;
          setTurns([...next, { role: "assistant", content: answer }]);
        } else if (e.type === "notice") setNotices((n) => [...n, e.text]);
        else if (e.type === "error") setError(e.message);
        else if (e.type === "done") setMeta(`${e.model} · ${e.input_tokens} jetons en entrée, ${e.output_tokens} en sortie`);
      }, abort.current.signal);
    } catch (err) {
      if (!(err instanceof DOMException && err.name === "AbortError")) setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
      if (!answer) {
        setTurns(history); // échec : on revient à l'état précédent, la question reste modifiable
        if (history.length || !initialQuestion) setDraft(question);
      }
    }
  };

  useEffect(() => {
    if (autoStart && initialQuestion && status?.enabled && !started.current) {
      started.current = true;
      ask(initialQuestion, []);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const question = draft.trim();
    if (!question || busy) return;
    setDraft("");
    ask(question, turns.filter((t) => t.content));
  };

  if (status && !status.enabled) {
    return <p className="muted">Assistant IA non configuré : un administrateur peut l'activer dans Paramètres &gt; Assistant IA.</p>;
  }

  return (
    <div className="ai-conversation">
      {status && (
        <p className="ai-privacy small">
          {status.local
            ? `Modèle local (${status.model}) : aucune donnée ne quitte votre réseau.`
            : status.pseudonymize
              ? `Envoyé à ${status.model} : comptes, postes et IP internes pseudonymisés avant envoi.`
              : `Envoyé à ${status.model} sans pseudonymisation.`}{" "}
          L'IA conseille ; elle ne peut exécuter aucune action.
        </p>
      )}
      {!turns.length && initialQuestion && !autoStart && (
        <button className="primary" disabled={!status?.enabled} onClick={() => ask(initialQuestion, [])}>
          Analyser avec l'IA
        </button>
      )}
      {turns.map((t, i) =>
        t.role === "user" ? (
          i === 0 && initialQuestion && t.content === initialQuestion ? null : (
            <div key={i} className="ai-question">{t.content}</div>
          )
        ) : (
          <div key={i} className="ai-answer">
            {t.content ? <Markdown text={t.content} /> : <span className="muted">Analyse en cours…</span>}
          </div>
        ),
      )}
      {notices.map((n) => <p key={n} className="ai-notice small">{n}</p>)}
      {error && <p className="form-error">{error}</p>}
      {meta && !busy && <p className="muted small">{meta}</p>}
      {(turns.length > 0 || !initialQuestion) && (
        <form className="ai-input" onSubmit={submit}>
          <textarea rows={2} value={draft} maxLength={4000} placeholder={placeholder} onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) submit(e); }} />
          {busy ? (
            <button type="button" onClick={() => abort.current?.abort()}>Arrêter</button>
          ) : (
            <button type="submit" className="primary" disabled={!draft.trim()}>Envoyer</button>
          )}
        </form>
      )}
    </div>
  );
}
