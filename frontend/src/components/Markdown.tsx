import { Fragment, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";

/**
 * Rendu Markdown minimal en éléments React : aucun HTML n'est interprété (la réponse d'une IA peut reprendre du
 * contenu de journaux contrôlé par un attaquant). Titres, listes, gras, code, blocs de code (avec copie), tableaux,
 * encadrés (« > »). `links` : les références « alerte n° 123 », « incident n° 4 » deviennent des liens (réponses IA).
 */
export default function Markdown({ text, links = false }: { text: string; links?: boolean }) {
  const inline = (t: string) => formatInline(t, links);
  const blocks: ReactNode[] = [];
  const lines = text.replace(/\r/g, "").split("\n");
  let list: { ordered: boolean; items: string[][] } | null = null;
  let paragraph: string[] = [];
  let quote: string[] = [];
  let table: string[][] | null = null;
  let code: string[] | null = null;

  const flushParagraph = () => {
    if (paragraph.length) blocks.push(<p key={blocks.length}>{inline(paragraph.join(" "))}</p>);
    paragraph = [];
  };
  const flushList = () => {
    if (!list) return;
    const items = list.items.map((item, i) => <li key={i}>{inline(item.join(" "))}</li>);
    blocks.push(list.ordered ? <ol key={blocks.length}>{items}</ol> : <ul key={blocks.length}>{items}</ul>);
    list = null;
  };
  const flushQuote = () => {
    if (quote.length) blocks.push(<div key={blocks.length} className="md-note">{inline(quote.join(" "))}</div>);
    quote = [];
  };
  const flushTable = () => {
    if (!table) return;
    const [head, ...rows] = table;
    blocks.push(
      <div key={blocks.length} className="md-table">
        <table>
          <thead>
            <tr>{head.map((c, i) => <th key={i}>{inline(c)}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>{r.map((c, j) => <td key={j}>{inline(c)}</td>)}</tr>
            ))}
          </tbody>
        </table>
      </div>,
    );
    table = null;
  };
  const flushAll = () => {
    flushParagraph();
    flushList();
    flushQuote();
    flushTable();
  };

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (code !== null) {
      if (/^\s*```/.test(line)) {
        blocks.push(<CodeBlock key={blocks.length} text={code.join("\n")} />);
        code = null;
      } else code.push(raw);
      continue;
    }
    if (/^\s*```/.test(line)) {
      flushAll();
      code = [];
      continue;
    }
    const cells = /^\s*\|(.*)\|\s*$/.exec(line);
    if (cells) {
      flushParagraph();
      flushList();
      flushQuote();
      const row = cells[1].split("|").map((c) => c.trim());
      if (row.every((c) => /^:?-{2,}:?$/.test(c))) continue; // ligne de séparation de l'en-tête
      table = table ?? [];
      table.push(row);
      continue;
    }
    flushTable();
    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    const ordered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    const bullet = /^\s*[-*•]\s+(.*)$/.exec(line);
    const quoted = /^\s*>\s?(.*)$/.exec(line);
    if (heading) {
      flushAll();
      const Tag = heading[1].length <= 1 ? "h3" : "h4";
      blocks.push(
        <Tag key={blocks.length} className={`md-heading md-tone-${headingTone(heading[2])}`}>
          {inline(heading[2])}
        </Tag>,
      );
    } else if (quoted) {
      flushParagraph();
      flushList();
      quote.push(quoted[1]);
    } else if (ordered || bullet) {
      flushParagraph();
      flushQuote();
      const isOrdered = Boolean(ordered);
      if (list && list.ordered !== isOrdered && !/^\s{2,}/.test(raw)) flushList();
      if (list && /^\s{2,}/.test(raw) && list.items.length) {
        list.items[list.items.length - 1].push(`· ${(ordered ?? bullet)![1]}`); // sous-élément : rattaché
      } else {
        list = list ?? { ordered: isOrdered, items: [] };
        list.items.push([(ordered ?? bullet)![1]]);
      }
    } else if (!line.trim()) {
      flushAll();
    } else if (list && /^\s{2,}/.test(raw)) {
      list.items[list.items.length - 1].push(line.trim()); // suite d'un élément de liste
    } else {
      flushList();
      flushQuote();
      paragraph.push(line.trim());
    }
  }
  if (code !== null) blocks.push(<CodeBlock key={blocks.length} text={(code as string[]).join("\n")} />);
  flushAll();
  return <div className="markdown">{blocks}</div>;
}

function CodeBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="md-code">
      <button type="button" className="md-copy" onClick={copy}>
        {copied ? "Copié" : "Copier"}
      </button>
      <pre>{text}</pre>
    </div>
  );
}

function formatInline(text: string, links: boolean): ReactNode[] {
  const parts: ReactNode[] = [];
  const plain = (s: string) => (links ? <Fragment key={parts.length}>{linkRefs(s)}</Fragment> : s);
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text))) {
    if (match.index > last) parts.push(plain(text.slice(last, match.index)));
    const token = match[0];
    parts.push(
      token.startsWith("**") ? <strong key={parts.length}>{linkRefsIf(token.slice(2, -2), links)}</strong> : <code key={parts.length}>{token.slice(1, -1)}</code>,
    );
    last = match.index + token.length;
  }
  if (last < text.length) parts.push(plain(text.slice(last)));
  return parts;
}

function linkRefsIf(text: string, links: boolean): ReactNode {
  return links ? linkRefs(text) : text;
}

/** Minuscules sans accents, pour comparer des mots. */
function fold(text: string): string {
  return text.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
}

/** Titre de section → teinte : l'IA structure ses analyses en Résumé, Évaluation, Actions recommandées, À vérifier. */
function headingTone(title: string): string {
  const t = fold(title);
  if (/resume|synthese|contexte|en bref/.test(t)) return "summary";
  if (/evaluation|verdict|diagnostic|risque|gravite|impact/.test(t)) return "assess";
  if (/action|recommand|remediation|mesure|correctif|que faire|blocage/.test(t)) return "action";
  if (/verifier|verification|controle|question|investigation|piste/.test(t)) return "check";
  return "other";
}

/*
 * « alerte n° 123 », « incidents n° 4 et 7 », « n° 123, 124 » (forme du contexte envoyé à l'IA : un « n° » seul
 * désigne une alerte). Un numéro précédé d'un mot comme « étape » ou « priorité » n'est pas une référence.
 */
const REF = /(?:\b(alertes?|incidents?)\s+)?(?:n[°º]|#)\s*(\d+)((?:\s*(?:,|et|ou)\s*(?:n[°º]\s*|#)?\d+)*)/giu;
const NOT_A_REF = /(?:^|[^\p{L}])(etapes?|actions?|priorites?|points?|options?|recommandations?|questions?|articles?|versions?|lignes?|pages?|niveaux?|phases?|regles?|tickets?|kb)\s*$/u;

function linkRefs(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let match: RegExpExecArray | null;
  REF.lastIndex = 0;
  while ((match = REF.exec(text))) {
    const [whole, keyword, first, tail] = match;
    if (!keyword) {
      if (NOT_A_REF.test(fold(text.slice(0, match.index)))) continue;
    }
    const base = keyword?.toLowerCase().startsWith("incident") ? "/incidents/" : "/alerts/";
    if (match.index > last) out.push(text.slice(last, match.index));
    const head = whole.slice(0, whole.length - tail.length);
    out.push(<Link key={out.length} className="md-ref" to={base + first}>{head}</Link>);
    // Suite d'une énumération (« , 124 et 125 ») : un nombre bien plus court que le premier n'est pas un numéro.
    let rest = tail;
    for (let m = /\d+/.exec(rest); m; m = /\d+/.exec(rest)) {
      out.push(rest.slice(0, m.index));
      out.push(m[0].length >= Math.min(2, first.length) && m[0].length >= first.length - 1
        ? <Link key={out.length} className="md-ref" to={base + m[0]}>{m[0]}</Link>
        : m[0]);
      rest = rest.slice(m.index + m[0].length);
    }
    if (rest) out.push(rest);
    last = match.index + whole.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}
