import { Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

export interface PickerModel {
  id: string;
  label: string;
  retired?: boolean;
}

const MAX_SHOWN = 200;

/** Choix d'un modèle avec recherche (fournisseurs à centaines de modèles, ex. OpenRouter).
 * La saisie filtre par nom ou identifiant (plusieurs mots possibles) ; un identifiant hors liste reste accepté. */
export default function ModelPicker({ models, value, onChange, placeholder }: {
  models: PickerModel[];
  value: string;
  onChange: (id: string) => void;
  placeholder?: string;
}) {
  const [query, setQuery] = useState(value);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [typing, setTyping] = useState(false); // liste complète à l'ouverture, filtrée dès la première frappe
  const listRef = useRef<HTMLUListElement>(null);

  useEffect(() => setQuery(value), [value]);

  const matches = useMemo(() => {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (!typing || !words.length) return models;
    return models.filter((m) => {
      const text = `${m.label} ${m.id}`.toLowerCase();
      return words.every((w) => text.includes(w));
    });
  }, [models, query, typing]);

  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const choose = (id: string) => {
    onChange(id);
    setQuery(id);
    setOpen(false);
    setTyping(false);
  };
  /** Sortie du champ : un identifiant exact (ou toute saisie si aucune liste) est retenu, sinon on revient au modèle choisi. */
  const commitOrRevert = () => {
    const typed = query.trim();
    if (typed && typed !== value && (models.length === 0 || models.some((m) => m.id === typed))) onChange(typed);
    else setQuery(value);
    setOpen(false);
    setTyping(false);
  };
  const selected = models.find((m) => m.id === value);

  return (
    <div className="model-picker">
      <div className="model-picker-input">
        <Search size={14} />
        <input
          role="combobox"
          aria-expanded={open}
          aria-autocomplete="list"
          value={query}
          placeholder={placeholder ?? "Rechercher un modèle (nom ou identifiant)"}
          onFocus={(e) => {
            setOpen(true);
            setTyping(false);
            e.target.select();
          }}
          onBlur={commitOrRevert}
          onChange={(e) => {
            setQuery(e.target.value);
            setTyping(true);
            setOpen(true);
            setActive(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setOpen(true);
              setActive((a) => Math.min(a + 1, Math.min(matches.length, MAX_SHOWN) - 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setActive((a) => Math.max(a - 1, 0));
            } else if (e.key === "Enter") {
              e.preventDefault();
              if (open && matches[active]) choose(matches[active].id);
              else if (query.trim()) choose(query.trim()); // identifiant hors liste, validé explicitement
            } else if (e.key === "Escape") {
              setQuery(value);
              setOpen(false);
              setTyping(false);
            }
          }}
        />
        {models.length > 0 && <span className="muted small">{open ? `${matches.length} / ${models.length}` : `${models.length} modèles`}</span>}
      </div>
      {selected && !open && selected.label !== selected.id && <div className="muted small">{selected.label}</div>}
      {open && models.length > 0 && (
        <ul className="model-picker-list" role="listbox" ref={listRef}>
          {matches.length === 0 && (
            <li className="muted small empty">Aucun modèle ne correspond. Entrée : utiliser « {query.trim()} » comme identifiant.</li>
          )}
          {matches.slice(0, MAX_SHOWN).map((m, i) => (
            <li
              key={m.id}
              role="option"
              data-index={i}
              aria-selected={m.id === value}
              className={`${i === active ? "active" : ""} ${m.id === value ? "selected" : ""}`}
              onMouseDown={(e) => {
                e.preventDefault();
                choose(m.id);
              }}
              onMouseEnter={() => setActive(i)}
            >
              <span>
                {m.label}
                {m.retired && <span className="text-bad small"> (retiré)</span>}
              </span>
              {m.label !== m.id && <code>{m.id}</code>}
            </li>
          ))}
          {matches.length > MAX_SHOWN && <li className="muted small empty">… affinez la recherche ({matches.length - MAX_SHOWN} autres)</li>}
        </ul>
      )}
    </div>
  );
}
