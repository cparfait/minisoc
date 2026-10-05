import { useState, type ReactNode } from "react";

/**
 * Rendu Markdown minimal en éléments React : aucun HTML n'est interprété (la réponse d'une IA peut reprendre du
 * contenu de journaux contrôlé par un attaquant). Titres, listes, gras, code, blocs de code (avec copie), tableaux,
 * encadrés (« > »).
 */
export default function Markdown({ text }: { text: string }) {
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
      blocks.push(<Tag key={blocks.length} className="md-heading">{inline(heading[2])}</Tag>);
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

function inline(text: string): ReactNode[] {
  const parts: ReactNode[] = [];
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text))) {
    if (match.index > last) parts.push(text.slice(last, match.index));
    const token = match[0];
    parts.push(
      token.startsWith("**") ? <strong key={parts.length}>{token.slice(2, -2)}</strong> : <code key={parts.length}>{token.slice(1, -1)}</code>,
    );
    last = match.index + token.length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}
