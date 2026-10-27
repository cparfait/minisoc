import { Download, GitCompareArrows } from "lucide-react";
import { useState, type CSSProperties } from "react";
import { api } from "../api";
import { usePolling } from "../hooks";
import { timeAgo } from "../labels";
import { Card, Empty } from "./ui";

type Source = "ninjaone" | "bitdefender" | "harfanglab" | "ad";

interface Row {
  name: string;
  server: boolean;
  ninjaone: boolean;
  bitdefender: boolean;
  harfanglab: boolean;
  ad: boolean;
  bitdefender_group: string;
  bitdefender_state: string;
  ninjaone_seen: string | null;
  harfanglab_seen: string | null;
  ad_seen: string | null;
  ad_service: string;
  os: string;
  doublons: Record<string, number>;
  issues: string[];
}

interface Cross {
  at: string;
  machines: number;
  sources: Record<Source, { read: boolean; count: number }>;
  summary: Record<string, number>;
  rows: Row[];
}

const SOURCES: { id: Source; label: string }[] = [
  { id: "ninjaone", label: "NinjaOne" },
  { id: "bitdefender", label: "Bitdefender" },
  { id: "harfanglab", label: "HarfangLab" },
  { id: "ad", label: "AD" },
];

// Constats du ménage (minisoc/inventory_cross.py) : libellé court, ton
const ISSUES: Record<string, { label: string; tone: string }> = {
  hors_ad: { label: "Hors AD", tone: "sev-high" },
  ad_desactive: { label: "Compte AD désactivé", tone: "sev-high" },
  ad_inactive: { label: "AD inactif (90 j)", tone: "sev-medium" },
  absent_ninjaone: { label: "Pas dans NinjaOne", tone: "sev-medium" },
  absent_bitdefender: { label: "Pas de Bitdefender", tone: "sev-critical" },
  absent_harfanglab: { label: "Pas de HarfangLab", tone: "sev-critical" },
  inactif_ninjaone: { label: "NinjaOne muet (30 j)", tone: "sev-medium" },
  inactif_harfanglab: { label: "HarfangLab muet (30 j)", tone: "sev-medium" },
  doublon_ninjaone: { label: "Doublon NinjaOne", tone: "sev-low" },
  doublon_bitdefender: { label: "Doublon Bitdefender", tone: "sev-low" },
  doublon_harfanglab: { label: "Doublon HarfangLab", tone: "sev-low" },
  doublon_ad: { label: "Doublon AD", tone: "sev-low" },
};
const label = (code: string) => ISSUES[code]?.label ?? code;

// Vues du ménage : chacune répond à une question et dit quoi faire
const VIEWS: { id: string; title: string; codes: string[]; tone: string; hint: string }[] = [
  { id: "all", title: "Tout", codes: [], tone: "var(--accent)", hint: "Toutes les machines qui demandent une vérification." },
  { id: "hors_ad", title: "Hors AD", codes: ["hors_ad"], tone: "var(--high)",
    hint: "Présentes dans un outil mais absentes de l'AD : machines d'école à confirmer (Bitdefender), sinon reliquats à retirer des outils." },
  { id: "obsolete", title: "Obsolètes", codes: ["ad_desactive", "ad_inactive", "inactif_ninjaone", "inactif_harfanglab"], tone: "var(--medium)",
    hint: "Compte AD désactivé ou sans connexion depuis 90 jours, ou agent sans contact depuis 30 jours : machine sans doute retirée du parc, à supprimer des outils." },
  { id: "protection", title: "Protection manquante", codes: ["absent_bitdefender", "absent_harfanglab"], tone: "var(--critical)",
    hint: "Bitdefender est attendu sur toutes les machines Windows et macOS, HarfangLab sur celles de l'AD : installer l'agent ou vérifier la machine." },
  { id: "ninja", title: "Absentes de NinjaOne", codes: ["absent_ninjaone"], tone: "var(--low)", hint: "Machines connues ailleurs mais pas supervisées par NinjaOne." },
  { id: "doublons", title: "Doublons", codes: ["doublon_ninjaone", "doublon_bitdefender", "doublon_harfanglab", "doublon_ad"], tone: "var(--info)",
    hint: "Plusieurs fiches pour la même machine dans un même outil : supprimer les anciennes." },
];

const day = (d: string | null) => (d ? new Date(d).toLocaleDateString("fr-FR", { timeZone: "Europe/Paris" }) : "");

function csvText(rows: Row[]): string {
  const esc = (v: unknown) => {
    const s = v === null || v === undefined ? "" : String(v);
    return /[";\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const head = ["Machine", "Type", "Système", "NinjaOne", "Bitdefender", "Groupe Bitdefender", "État Bitdefender", "HarfangLab", "AD",
    "Service AD", "Dernier contact NinjaOne", "Dernier contact HarfangLab", "Dernière session AD", "À régler"];
  const yes = (b: boolean) => (b ? "oui" : "non");
  const lines = rows.map((r) => [r.name, r.server ? "serveur" : "poste", r.os, yes(r.ninjaone), yes(r.bitdefender), r.bitdefender_group,
    r.bitdefender_state, yes(r.harfanglab), yes(r.ad), r.ad_service, day(r.ninjaone_seen), day(r.harfanglab_seen), day(r.ad_seen),
    r.issues.map(label).join(" | ")]);
  return [head, ...lines].map((l) => l.map(esc).join(";")).join("\n");
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob(["﻿" + text], { type: "text/csv;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

/** Pastille d'un outil : présente (vert), absente à régulariser (rouge), absente sans conséquence (gris), non lu (pointillé). */
function Chip({ name, state, detail }: { name: string; state: "ok" | "flag" | "off" | "unk"; detail?: string }) {
  const mark = state === "ok" ? "✓" : state === "flag" ? "✗" : state === "unk" ? "?" : "–";
  return (
    <span className={`src-chip ${state}`} title={state === "unk" ? "Source non lue : aucune conclusion" : undefined}>
      <span>{mark} {name}</span>
      {detail && <em>{detail}</em>}
    </span>
  );
}

/** Veille : machines présentes dans un outil et absentes d'un autre ou de l'AD (ménage des consoles), export CSV. */
export default function InventoryCross() {
  const { data } = usePolling(() => api<{ cross: Cross | null }>("/inventory/cross"), [], 300000);
  const [view, setView] = useState("all");
  const [present, setPresent] = useState<"" | Source>("");
  const [absent, setAbsent] = useState<"" | Source>("");
  const [text, setText] = useState("");
  const cross = data?.cross;
  const current = VIEWS.find((v) => v.id === view) ?? VIEWS[0];
  const inView = (r: Row, v: (typeof VIEWS)[number]) => !v.codes.length || r.issues.some((i) => v.codes.includes(i));

  const rows = (cross?.rows ?? []).filter(
    (r) =>
      inView(r, current) &&
      (!present || r[present]) &&
      (!absent || !r[absent]) &&
      (!text || `${r.name} ${r.bitdefender_group} ${r.ad_service} ${r.os}`.toLowerCase().includes(text.toLowerCase())),
  );
  const chip = (r: Row, s: { id: Source; label: string }) => {
    if (!cross?.sources[s.id].read) return <Chip key={s.id} name={s.label} state="unk" />;
    const flagged = r.issues.includes(s.id === "ad" ? "hors_ad" : `absent_${s.id}`);
    if (!r[s.id]) return <Chip key={s.id} name={s.label} state={flagged ? "flag" : "off"} detail={flagged ? "absente" : undefined} />;
    if (s.id === "bitdefender") {
      return <Chip key={s.id} name={s.label} state="ok"
        detail={`${r.bitdefender_group || "groupe ?"}${r.bitdefender_state === "non géré" ? " · non géré" : ""}`} />;
    }
    const seen = day(s.id === "ninjaone" ? r.ninjaone_seen : s.id === "harfanglab" ? r.harfanglab_seen : r.ad_seen);
    return <Chip key={s.id} name={s.label} state="ok" detail={seen ? `vu le ${seen}` : undefined} />;
  };

  return (
    <Card title="Croisement NinjaOne · Bitdefender · HarfangLab · AD" icon={GitCompareArrows}>
      {!cross ? (
        <p className="muted">Pas encore de relevé : il est fait avec la vérification de couverture (une heure après le démarrage au plus).</p>
      ) : (
        <>
          <p className="small">
            {cross.machines} machines distinctes, {cross.rows.length} à vérifier · relevé {timeAgo(cross.at)} ·{" "}
            {SOURCES.map((s) => (
              <span key={s.id}>
                {s.label} : {cross.sources[s.id].read ? cross.sources[s.id].count : <em>non lu</em>}
                {s.id !== "ad" && " · "}
              </span>
            ))}
          </p>
          <div className="cross-tiles">
            {VIEWS.map((v) => (
              <button key={v.id} type="button" className={`cross-tile${v.id === view ? " active" : ""}`}
                style={{ "--tone": v.tone } as CSSProperties} onClick={() => setView(v.id)}>
                <b>{cross.rows.filter((r) => inView(r, v)).length}</b>
                <span>{v.title}</span>
              </button>
            ))}
          </div>
          <p className="cross-hint">{current.hint}</p>
          <div className="filters">
            <input type="search" placeholder="Machine, groupe Bitdefender, système" value={text} onChange={(e) => setText(e.target.value)} />
            <select value={present} onChange={(e) => setPresent(e.target.value as "" | Source)} aria-label="Présente dans">
              <option value="">Présente dans : n'importe quel outil</option>
              {SOURCES.map((s) => <option key={s.id} value={s.id}>Présente dans {s.label}</option>)}
            </select>
            <select value={absent} onChange={(e) => setAbsent(e.target.value as "" | Source)} aria-label="Absente de">
              <option value="">Absente de : aucun filtre</option>
              {SOURCES.map((s) => <option key={s.id} value={s.id}>Absente de {s.label}</option>)}
            </select>
            <button type="button" className="ghost small" disabled={!rows.length}
              onClick={() => download(`croisement-inventaires-${new Date().toISOString().slice(0, 10)}.csv`, csvText(rows))}>
              <Download size={14} /> Export CSV ({rows.length})
            </button>
          </div>
          {!rows.length ? (
            <Empty>Aucune machine ne correspond.</Empty>
          ) : (
            <div className="table-scroll">
              <table className="assets-table">
                <thead>
                  <tr>
                    <th>Machine</th>
                    <th>Où elle est</th>
                    <th>À régler</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.slice(0, 500).map((r) => (
                    <tr key={r.name}>
                      <td>
                        <strong>{r.name}</strong> {r.server && <span className="badge sev-info">serveur</span>}
                        <div className="muted small">{[r.os, r.ad_service].filter(Boolean).join(" · ")}</div>
                      </td>
                      <td><div className="src-chips">{SOURCES.map((s) => chip(r, s))}</div></td>
                      <td>
                        <div className="todo-list">
                          {r.issues.map((i) => <span key={i} className={`badge ${ISSUES[i]?.tone ?? "sev-info"}`}>{label(i)}</span>)}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {rows.length > 500 && <p className="muted small">500 premières lignes affichées sur {rows.length} : l'export CSV les contient toutes.</p>}
            </div>
          )}
        </>
      )}
    </Card>
  );
}
