import { CircleAlert, CircleCheck, Copy, ExternalLink, Info, SearchCheck } from "lucide-react";
import { type ReactNode, useState } from "react";
import { formatDate } from "../labels";
import type { EventRow } from "../types";
import { Card } from "./ui";

/** Levée de doute : éléments de contexte extraits de l'alerte d'origine (HarfangLab), avec des indices
 * rassurants ou suspects calculés sur le processus, sa signature, sa ligne de commande et sa session. */

type Raw = Record<string, unknown>;

function get(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((o, k) => (o && typeof o === "object" ? (o as Raw)[k] : undefined), obj);
}

function str(obj: unknown, ...paths: string[]): string {
  for (const p of paths) {
    const v = get(obj, p);
    if (v !== undefined && v !== null && v !== "") return Array.isArray(v) ? v.join(", ") : String(v);
  }
  return "";
}

function parse(raw: string): Raw | null {
  try {
    const value = JSON.parse(raw);
    return value && typeof value === "object" ? (value as Raw) : null;
  } catch {
    return null;
  }
}

const LOGON_TYPES: Record<string, string> = {
  "2": "ouverture de session sur le poste",
  "3": "accès réseau",
  "4": "tâche planifiée (batch)",
  "5": "service Windows",
  "7": "déverrouillage de session",
  "8": "réseau, mot de passe en clair",
  "9": "nouvelles informations d'identification (runas)",
  "10": "bureau à distance (RDP)",
  "11": "session mise en cache (hors réseau)",
};

const DETECTION_TYPES: Record<string, string> = {
  sigma: "règle comportementale (Sigma)",
  yara: "signature de fichier (YARA)",
  ioc: "indicateur de compromission (IOC)",
  hlai: "IA HarfangLab (binaire)",
  hlaiscripts: "IA HarfangLab (script)",
  driverblock: "liste de pilotes vulnérables",
  ransomguard: "protection anti-rançongiciel",
  hips: "comportement (HIPS)",
};

/** Outils connus dans la chaîne de processus : aident à comprendre qui a lancé quoi. */
const KNOWN_TOOLS: [RegExp, string][] = [
  [/\\claude(-code)?\\.*claude\.exe|\\claude\.exe$/i, "Claude Code (assistant IA de développement)"],
  [/\\code\.exe$/i, "Visual Studio Code"],
  [/\\sragent\\/i, "agent Netwrix (sragent)"],
  [/ninjarmm|ninjaone/i, "agent NinjaOne"],
  [/teamviewer/i, "TeamViewer (prise en main à distance)"],
  [/anydesk/i, "AnyDesk (prise en main à distance)"],
  [/\\wsmprovhost\.exe$/i, "PowerShell à distance (WinRM)"],
  [/\\psexesvc\.exe$/i, "PsExec (exécution à distance)"],
  [/\\(winword|excel|powerpnt|outlook)\.exe$/i, "Microsoft Office"],
  [/\\(chrome|msedge|firefox)\.exe$/i, "navigateur web"],
];

interface Hint {
  tone: "ok" | "warn" | "info";
  text: string;
}

function hints(r: Raw): Hint[] {
  const out: Hint[] = [];
  const image = str(r, "process.image_name", "image_name");
  const cmd = str(r, "process.commandline");
  const script = str(r, "details_powershell.PowershellCommand");
  const text = `${cmd}\n${script}`;
  const signer = str(r, "process.signature_info.signer_info.display_name");
  const signature = str(r, "process.signature_info.status");
  const execution = get(r, "execution");

  if (execution === 0 || execution === "0") out.push({ tone: "info", text: "Détecté par l'EDR, mais non bloqué : le programme s'est exécuté." });
  else if (execution !== undefined) out.push({ tone: "ok", text: "Exécution bloquée par l'EDR." });
  if (image) {
    if (signature === "VALID" && signer) out.push({ tone: "ok", text: `Programme signé par « ${signer} » (signature valide).` });
    else if (signature && signature !== "VALID") out.push({ tone: "warn", text: `Signature du programme : ${signature}.` });
    else if (str(r, "process.signed") === "false") out.push({ tone: "warn", text: "Programme non signé." });
    if (/\\(appdata|temp|downloads|téléchargements|users\\public|programdata)\\/i.test(image)) {
      out.push({ tone: "warn", text: "Programme lancé depuis un dossier modifiable par l'utilisateur (AppData, Temp, Téléchargements…)." });
    }
  }
  if (/-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string/i.test(text)) out.push({ tone: "warn", text: "Commande encodée en Base64 (technique de dissimulation courante)." });
  if (/downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|bitsadmin|certutil.+-urlcache|https?:\/\//i.test(text)) {
    out.push({ tone: "warn", text: "Téléchargement ou accès à une adresse web dans la commande." });
  }
  if (/-w(indowstyle)?\s+hidden|-noni(nteractive)?\b/i.test(text)) out.push({ tone: "info", text: "Exécution sans fenêtre / non interactive (outils d'administration comme attaquants)." });
  if (/executionpolicy\s+bypass|-ep\s+bypass/i.test(text)) out.push({ tone: "info", text: "Contournement de la stratégie d'exécution PowerShell (fréquent chez les outils légitimes aussi)." });
  const chain = [str(r, "process.ancestors"), str(r, "process.grandparent_image"), str(r, "process.parent_image"), image].join("|");
  const tools = new Set(KNOWN_TOOLS.filter(([re]) => chain.split("|").some((p) => re.test(p))).map(([, label]) => label));
  for (const t of tools) out.push({ tone: "info", text: `Lancé via ${t}.` });
  const logon = str(r, "process_session.logon_type", "event_session.logon_type");
  if (logon === "10") out.push({ tone: "warn", text: `Session ouverte à distance (RDP) depuis ${str(r, "process_session.source_windows_hostname", "process_session.source_windows_ip") || "une machine inconnue"}.` });
  if (logon === "3") out.push({ tone: "info", text: "Action réalisée par un accès réseau (autre machine)." });
  const score = Number(get(r, "hlai_binaries_benchmark_data.condor_prediction"));
  if (!Number.isNaN(score) && score > 0) out.push({ tone: score >= 0.9 ? "warn" : "info", text: `Score de l'IA HarfangLab : ${Math.round(score * 100)} % de probabilité de malveillance.` });
  return out;
}

function ruleDescription(r: Raw): string {
  const content = str(r, "rule_content", "process.sigma_rule_content");
  const match = content.match(/^description:\s*\|?\s*\n?((?:[ \t]+.*\n?)+|.*)/m);
  return (match?.[1] ?? "").replace(/^\s+/gm, "").trim() || str(r, "msg");
}

function mitre(r: Raw): string[] {
  const tags = (get(r, "tags") as string[] | undefined) ?? [];
  return [...new Set(tags.filter((t) => /^attack\.t\d{4}/i.test(t)).map((t) => t.slice(7).toUpperCase()))];
}

function Copyable({ value, long = false }: { value: string; long?: boolean }) {
  const [done, setDone] = useState(false);
  if (!value) return <span className="muted">—</span>;
  return (
    <span className={`triage-value ${long ? "long" : ""}`}>
      <code>{value}</code>
      <button type="button" className="icon-button" title="Copier" onClick={() => navigator.clipboard.writeText(value).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); })}>
        {done ? <CircleCheck size={13} /> : <Copy size={13} />}
      </button>
    </span>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  );
}

function Hash({ value }: { value: string }) {
  if (!value) return <span className="muted">—</span>;
  return (
    <span className="triage-hash">
      <Copyable value={value} />
      <a href={`https://www.virustotal.com/gui/file/${encodeURIComponent(value)}`} target="_blank" rel="noopener noreferrer" className="triage-ref" title="Rechercher l'empreinte sur VirusTotal (seule l'empreinte est transmise)">
        VirusTotal <ExternalLink size={12} />
      </a>
    </span>
  );
}

export default function Triage({ events }: { events: EventRow[] }) {
  const parsed = events
    .filter((e) => e.module === "harfanglab" && e.raw)
    .map((e) => ({ event: e, raw: parse(e.raw) }))
    .filter((x): x is { event: EventRow; raw: Raw } => x.raw !== null)
    .sort((a, b) => b.event.ts.localeCompare(a.event.ts));
  if (!parsed.length) return null;
  const r = parsed[0].raw;
  const list = hints(r);
  const techniques = mitre(r);
  const description = ruleDescription(r);
  const references = ((get(r, "references") as string[] | undefined) ?? []).filter((u) => /^https:\/\//.test(u));
  const logon = str(r, "process_session.logon_type", "event_session.logon_type");
  const script = str(r, "details_powershell.PowershellCommand");
  const commandLines = [...new Set(parsed.map((p) => str(p.raw, "process.commandline")).filter(Boolean))];
  const detectionType = str(r, "alert_type");
  const ancestors = str(r, "process.ancestors").split("|").filter(Boolean).reverse();

  return (
    <Card title="Levée de doute" icon={SearchCheck} className="triage-card">
      {list.length > 0 && (
        <ul className="triage-hints">
          {list.map((h) => (
            <li key={h.text} className={h.tone}>
              {h.tone === "ok" ? <CircleCheck size={15} /> : h.tone === "warn" ? <CircleAlert size={15} /> : <Info size={15} />}
              {h.text}
            </li>
          ))}
        </ul>
      )}

      <div className="triage-grid">
        <section>
          <h4>Détection</h4>
          <dl className="triage-dl">
            <Row label="Type">{DETECTION_TYPES[detectionType] ?? (detectionType || "—")}</Row>
            <Row label="Niveau / confiance">
              {[str(r, "level"), str(r, "confidence"), str(r, "maturity")].filter(Boolean).join(" · ") || "—"}
            </Row>
            {description && <Row label="Ce que détecte la règle">{description}</Row>}
            {techniques.length > 0 && (
              <Row label="MITRE ATT&CK">
                {techniques.map((t) => (
                  <a key={t} className="triage-tag" href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer">
                    {t}
                  </a>
                ))}
              </Row>
            )}
            {str(r, "detection.file_path") && <Row label="Fichier détecté"><Copyable value={str(r, "detection.file_path")} /></Row>}
            {str(r, "threat_values") && !script && <Row label="Élément en cause"><Copyable value={str(r, "threat_values")} long /></Row>}
            {references.length > 0 && (
              <Row label="Références">
                {references.slice(0, 3).map((u) => (
                  <a key={u} href={u} target="_blank" rel="noopener noreferrer" className="triage-ref">
                    {new URL(u).hostname} <ExternalLink size={11} />
                  </a>
                ))}
              </Row>
            )}
          </dl>
        </section>

        <section>
          <h4>Qui et où</h4>
          <dl className="triage-dl">
            <Row label="Compte">{str(r, "process.username", "process_session.target_username") || "—"}</Row>
            <Row label="Type de session">{logon ? `${LOGON_TYPES[logon] ?? "autre"} (type ${logon})` : "—"}</Row>
            {str(r, "process_session.source_windows_hostname") && (
              <Row label="Session ouverte depuis">
                {str(r, "process_session.source_windows_hostname")} {str(r, "process_session.source_windows_ip") && `(${str(r, "process_session.source_windows_ip")})`}
              </Row>
            )}
            <Row label="Privilèges">{str(r, "process.integrity_level") || "—"}</Row>
            <Row label="Dossier courant">{str(r, "process.current_directory") ? <Copyable value={str(r, "process.current_directory")} /> : "—"}</Row>
            <Row label="Groupe HarfangLab">{str(r, "groups.0.name") || "—"}</Row>
            <Row label="Machine">
              {str(r, "agent.hostname")} {str(r, "agent.osproducttype") && <span className="muted">· {str(r, "agent.osproducttype")}</span>}
            </Row>
          </dl>
        </section>
      </div>

      {(str(r, "process.image_name") || ancestors.length > 0) && (
        <section>
          <h4>Chaîne de processus</h4>
          <ol className="triage-tree">
            {ancestors.length > 0
              ? ancestors.map((p, i) => (
                  <li key={`${i}-${p}`} className={i === ancestors.length - 1 ? "current" : ""}>
                    <code>{p}</code>
                  </li>
                ))
              : [str(r, "process.grandparent_image"), str(r, "process.parent_image"), str(r, "process.image_name")].filter(Boolean).map((p, i, all) => (
                  <li key={`${i}-${p}`} className={i === all.length - 1 ? "current" : ""}>
                    <code>{p}</code>
                  </li>
                ))}
          </ol>
          <dl className="triage-dl">
            {str(r, "process.parent_commandline") && <Row label="Commande du parent"><Copyable value={str(r, "process.parent_commandline")} long /></Row>}
            {commandLines.length > 0 && (
              <Row label={commandLines.length > 1 ? `Commandes (${commandLines.length} différentes)` : "Commande"}>
                {commandLines.slice(0, 5).map((c) => (
                  <Copyable key={c} value={c} long />
                ))}
              </Row>
            )}
            <Row label="Programme">
              {[str(r, "process.pe_info.file_description"), str(r, "process.pe_info.company_name"), str(r, "process.pe_info.product_version")].filter(Boolean).join(" · ") || "—"}
            </Row>
            <Row label="Empreinte SHA-256"><Hash value={str(r, "process.hashes.sha256", "detection.file_hashes.sha256")} /></Row>
          </dl>
        </section>
      )}

      {script && (
        <section>
          <h4>Script PowerShell analysé</h4>
          <Copyable value={script} long />
          <dl className="triage-dl">
            <Row label="Empreinte du script"><Hash value={str(r, "details_powershell.sha256", "details_powershell.hashes.sha256")} /></Row>
          </dl>
        </section>
      )}

      {parsed.length > 1 && (
        <section>
          <h4>Occurrences ({parsed.length})</h4>
          <table className="triage-occurrences">
            <tbody>
              {parsed.slice(0, 10).map(({ event, raw }) => (
                <tr key={event.event_id}>
                  <td className="nowrap">{formatDate(event.ts)}</td>
                  <td className="mono small">{str(raw, "process.commandline", "detection.file_path", "threat_values").slice(0, 220) || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </Card>
  );
}
