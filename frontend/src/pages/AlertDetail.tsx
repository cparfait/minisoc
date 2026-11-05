import {
  ArrowLeft, Ban, BookOpen, ChevronLeft, ChevronRight, ClipboardCheck, ExternalLink, Hand, History, Layers, ScrollText, ShieldAlert,
  ShieldCheck, ShieldHalf, Sparkles, Unplug,
} from "lucide-react";
import { type ReactNode, useLayoutEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { type AlertNeighbours, useAlertNeighbours } from "../alertNav";
import { api } from "../api";
import { canEdit, useUser } from "../App";
import { DetectionName, ToolBadge } from "../components/AlertBits";
import AIConversation from "../components/AIConversation";
import BlockPanel from "../components/BlockPanel";
import BlockSummary from "../components/BlockSummary";
import EventTable from "../components/EventTable";
import ExceptionFromAlert from "../components/ExceptionFromAlert";
import { OverdueBadge, ToolActions, ToolStateLine, WAITING_REASONS, toolActionsTitle, useAssignees, waitingLabel } from "../components/Followup";
import Markdown from "../components/Markdown";
import NinjaTicket from "../components/NinjaTicket";
import { CategoryBadge, PriorityPill, PriorityReasons } from "../components/Priority";
import { SourceClosureNote } from "../components/SourceClosure";
import RelatedAlerts from "../components/RelatedAlerts";
import { DerivedDetails } from "../components/Risk";
import Triage, { ToolTriage, threatState } from "../components/Triage";
import { HostChips, ImpactedHosts } from "../components/Hosts";
import IncidentPicker, { IncidentBadge } from "../components/IncidentPicker";
import IsolationPanel from "../components/IsolationPanel";
import { OgoSeen } from "../components/Ogo";
import { Card, ErrorBanner, Fold, MitreTags, SeverityBadge, StatusBadge, VerdictBadge } from "../components/ui";
import { usePolling } from "../hooks";
import { ACTION_LABEL, STATUS_LABEL, formatDate, formatNumber, moduleLabel, timeAgo } from "../labels";
import type { AlertDetail as Detail, AlertStatus, ImpactedHost, Qualification } from "../types";

const CLOSED: AlertStatus[] = ["resolved", "false_positive"];
const SEARCHABLE: Record<string, string> = { "source.ip": "ip", "user.name": "user", "host.name": "host" };
const FIELD_LABEL: Record<string, string> = { "event.module": "Source", "host.name": "Machine", "rule.name": "Détection",
  "source.ip": "Adresse IP", "user.name": "Compte" };
const VISIBLE_VALUES = 6;
/** Clôture rapide : le choix et le commentaire type restent à enregistrer, et le texte reste modifiable. */
const CLOSURES: { status: AlertStatus; comments: string[] }[] = [
  { status: "resolved", comments: ["Cause corrigée, vérification faite.", "Menace neutralisée par l'outil, poste vérifié.", "Utilisateur contacté : situation normale."] },
  { status: "false_positive", comments: ["Activité légitime vérifiée.", "Erreur d'utilisateur : mot de passe à mettre à jour.", "Détection non pertinente dans notre contexte."] },
];

/** « source.ip=1.2.3.4 | host.name=PC » → { "source.ip": "1.2.3.4", "host.name": "PC" } */
function entityParts(entity: string): Record<string, string> {
  return Object.fromEntries(entity.split(" | ").filter((part) => part.includes("=")).map((part) => {
    const at = part.indexOf("=");
    return [part.slice(0, at), part.slice(at + 1)];
  }).filter(([field, value]) => field && value));
}

const distinct = (values: unknown[]) =>
  [...new Set(values.map((v) => String(v ?? "").trim()).filter((v) => v && v !== "?"))];

/** Comptes et IP cités par l'alerte : entité, échantillons, entités regroupées, événements conservés. */
function citedValues(alert: Detail, entity: Record<string, string>, sample: Record<string, unknown>, groupedIps: string[]) {
  return {
    users: distinct([entity["user.name"], sample["user.name"], ...((alert.details.sample_users as string[] | undefined) ?? []), ...alert.events.map((e) => e.user_name)]),
    ips: distinct([entity["source.ip"], sample["source.ip"], ...((alert.details.sample_ips as string[] | undefined) ?? []), ...groupedIps, ...alert.events.map((e) => e.source_ip)]),
  };
}

/** Machines de l'alerte, y compris celles que seuls ses événements citent. */
function allHosts(alert: Detail): ImpactedHost[] {
  const known = new Set(alert.hosts.map((h) => h.name.toLowerCase()));
  return [
    ...alert.hosts,
    ...distinct(alert.events.map((e) => e.host_name)).filter((name) => !known.has(name.toLowerCase())).map((name) => ({ name, count: 0, rules: [] })),
  ];
}

export default function AlertDetail() {
  const { id } = useParams();
  const neighbours = useAlertNeighbours(Number(id));
  useLayoutEffect(() => {
    window.scrollTo(0, 0);
  }, [id]);
  // Une vue par alerte : la suivante repart d'un état vierge (commentaire en cours, machine choisie, formulaires ouverts)
  return <AlertView key={id} id={id ?? ""} neighbours={neighbours} />;
}

function AlertView({ id, neighbours }: { id: string; neighbours: AlertNeighbours }) {
  const user = useUser();
  const { data: alert, error, reload } = usePolling(() => api<Detail>(`/alerts/${id}`), [id], 30000);
  const [host, setHost] = useState<string | null>(null);

  if (!alert) {
    return (
      <>
        <AlertHead neighbours={neighbours} />
        {error ? <ErrorBanner error={error} /> : <p className="muted">Chargement de l'alerte…</p>}
      </>
    );
  }

  const editable = canEdit(user);
  const details = alert.details;
  const qualification = details.qualification as Qualification | undefined;
  const coverage = details.coverage as
    | { reason: string; seen_by: string[]; since?: string; bitdefender_group?: string | null; perimeter?: string | null }
    | undefined;
  const sample = (details.sample as Record<string, unknown> | undefined) ?? {};
  const entity = entityParts(alert.entity_key);
  const grouped = Object.entries((details.entities as Record<string, number> | undefined) ?? {}).sort((a, b) => b[1] - a[1]);
  // IP candidates au blocage : entité, IP observées, entités regroupées (anti-tempête)
  const groupedIps = grouped.map(([k]) => k).filter((k) => k.startsWith("source.ip=") && !k.includes(" | ")).map((k) => k.slice("source.ip=".length));
  const entityIp = alert.entity_key.startsWith("source.ip=") && !alert.entity_key.includes(" | ") ? [entity["source.ip"]] : [];
  const blockCandidates = [...new Set([...entityIp, ...((details.sample_ips as string[] | undefined) ?? []), ...groupedIps])];
  const hasMalwareSummary = alert.events.some((e) => e.module === "bitdefender" && e.category === "malware");
  const open = !CLOSED.includes(alert.status);
  const cited = citedValues(alert, entity, sample, groupedIps);
  const stormy = !!details.storm || grouped.length > 0;

  return (
    <>
      <AlertHead neighbours={neighbours} alert={alert} />
      <ErrorBanner error={error} />

      <div className="alert-layout">
        <div className="alert-main">
          <AlertSummary alert={alert} qualification={qualification} users={cited.users} ips={cited.ips} />
          {/* Tempête : ses IP sont trop nombreuses et trop diverses pour relier des alertes */}
          <RelatedAlerts alertId={alert.id} hosts={allHosts(alert).map((h) => h.name)} users={cited.users} ips={stormy ? [] : cited.ips} ipsSkipped={stormy && cited.ips.length > 0} />

          <DerivedDetails details={details} />
          {coverage && (
            <Card title="Couverture de la machine" icon={ShieldCheck}>
              <dl className="coverage-facts">
                <dt>Constat</dt>
                <dd><strong>{coverage.reason}</strong></dd>
                {coverage.perimeter && (
                  <>
                    <dt>Périmètre</dt>
                    <dd>
                      {coverage.perimeter === "AD" ? "Machine de l'AD : protégée par HarfangLab" : "Hors AD (écoles…) : protégée par Bitdefender"}
                    </dd>
                  </>
                )}
                {coverage.bitdefender_group !== undefined && coverage.bitdefender_group !== null && (
                  <>
                    <dt>Groupe Bitdefender</dt>
                    <dd>{coverage.bitdefender_group ? <span className="badge sev-low">{coverage.bitdefender_group}</span> : <span className="muted">aucun : la machine n'est pas dans GravityZone</span>}</dd>
                  </>
                )}
                <dt>Vue par</dt>
                <dd>{coverage.seen_by.map(moduleLabel).join(", ")}</dd>
                {coverage.since && (
                  <>
                    <dt>Depuis</dt>
                    <dd>{formatDate(coverage.since)}</dd>
                  </>
                )}
              </dl>
            </Card>
          )}
          <BlockSummary events={alert.events} massive={alert.rule_id === "UC-65"} total={alert.metric} />
          <ImpactedHosts hosts={alert.hosts} events={alert.events} selected={host} onSelect={setHost} folded={hasMalwareSummary} />
          <Triage events={alert.events} host={host} onReset={() => setHost(null)} />
          <ToolTriage events={alert.events} host={host} />
          {grouped.length > 0 && <GroupedEntities alert={alert} grouped={grouped} editable={editable} onDone={reload} />}
          <OgoSeen
            key={`ogo-${alert.id}`}
            ips={[...blockCandidates, String(sample["source.ip"] ?? "")]}
          />
          {editable && (
            <Fold title="Assistant IA" icon={Sparkles} className="card" defaultOpen>
              <AIConversation
                key={alert.id}
                path={`/ai/alerts/${alert.id}/analyze`}
                initialQuestion="Analyse cette alerte."
                placeholder="Question de suivi (ex. : comment bloquer ces IP sur le XGS ?)"
              />
            </Fold>
          )}
          <Fold title={`Événements liés (${alert.events.length})`} icon={ScrollText} className="card" hint="dates, IP, comptes, journaux bruts">
            <div className="table-scroll">
              <EventTable events={alert.events} />
            </div>
          </Fold>
        </div>

        <aside className="alert-rail" aria-label="Traitement et réponse">
          <Treatment alert={alert} editable={editable} next={neighbours.next} onDone={reload} />

          <Card title="Que faire" icon={Hand} className="alert-actions">
            <Fold title={toolActionsTitle(alert)} icon={ExternalLink} className="rail-fold">
              <ToolActions alert={alert} />
            </Fold>
            {editable && blockCandidates.length > 0 && (
              <Fold title="Bloquer sur le pare-feu" icon={Ban} className="rail-fold" hint={`${formatNumber(blockCandidates.length)} IP`}
                defaultOpen={open && qualification?.verdict === "attack" && blockCandidates.length <= 10}>
                <BlockPanel key={alert.id} alertId={alert.id} title={alert.title} candidates={blockCandidates} />
              </Fold>
            )}
            {editable && alert.modules.some((m) => m === "harfanglab" || m === "bitdefender") && (
              <Fold title="Isoler le poste (EDR)" icon={Unplug} className="rail-fold">
                <IsolationPanel key={alert.id} alertId={alert.id} onDone={reload} />
              </Fold>
            )}
            <NinjaTicket alertId={alert.id} ticket={alert.ticket} editable={editable} onDone={reload} />
            {alert.incident_id ? (
              <p className="alert-incident">
                <ShieldAlert size={15} /> Rattachée à l'<IncidentBadge id={alert.incident_id} /> : le traitement se suit dans l'incident.
              </p>
            ) : editable ? (
              <Fold title="Rattacher à un incident" icon={ShieldAlert} className="rail-fold">
                <IncidentPicker alertIds={[alert.id]} defaultTitle={alert.title} onDone={reload} />
              </Fold>
            ) : null}
            {editable && open && (
              <div className="exception-box">
                <ExceptionFromAlert alertId={alert.id} ruleId={alert.rule_id} entityKey={alert.entity_key} onDone={reload} />
              </div>
            )}
          </Card>

          <Fold title="Fiche réflexe" icon={BookOpen} className="card playbook" defaultOpen>
            {alert.playbook ? (
              // Rendu en éléments React : aucun HTML interprété ; le titre de la fiche redit celui du bloc
              <Markdown text={alert.playbook.replace(/^#\s+.*\n+/, "")} />
            ) : (
              <p className="muted small">Pas de fiche réflexe pour cette règle.</p>
            )}
          </Fold>
        </aside>
      </div>
    </>
  );
}

/** En-tête toujours visible : retour à la liste, alerte précédente ou suivante, gravité, qualification, statut. */
function AlertHead({ neighbours, alert }: { neighbours: AlertNeighbours; alert?: Detail }) {
  const { backTo, position, total, prev, next } = neighbours;
  const consoleName = alert?.modules.length ? moduleLabel(alert.modules[0]) : "l'outil d'origine";
  return (
    <header className="alert-head">
      <div className="alert-head-row">
        <Link to={backTo} className="alert-back" title="Retour à la liste : filtres et position conservés">
          <ArrowLeft size={15} /> Alertes
        </Link>
        {position !== null && (
          <span className="alert-steps">
            <StepLink to={prev} label="Alerte précédente de la liste"><ChevronLeft size={16} /></StepLink>
            <span className="small">{formatNumber(position)} / {formatNumber(total)}</span>
            <StepLink to={next} label="Alerte suivante de la liste"><ChevronRight size={16} /></StepLink>
          </span>
        )}
        {alert && (
          <>
            <span className="muted small">n° {alert.id}</span>
            <span className="spacer" />
            <span title="Priorité de traitement, sur 100"><PriorityPill score={alert.priority} reasons={alert.priority_reasons} /></span>
            <SeverityBadge severity={alert.severity} />
            <VerdictBadge verdict={alert.verdict} label={alert.verdict_label} />
            <CategoryBadge category={alert.category} />
            <StatusBadge status={alert.status} />
            <OverdueBadge alert={alert} />
            {alert.incident_id && <IncidentBadge id={alert.incident_id} />}
            {alert.reference && (
              <a className="button" href={alert.reference} target="_blank" rel="noopener noreferrer">
                Gérer dans {consoleName} <ExternalLink size={14} />
              </a>
            )}
          </>
        )}
      </div>
      {alert && <h1 title={alert.title}>{alert.title}</h1>}
    </header>
  );
}

function StepLink({ to, label, children }: { to: number | null; label: string; children: ReactNode }) {
  if (to === null) return <span className="alert-step disabled" aria-hidden>{children}</span>;
  return <Link to={`/alerts/${to}`} className="alert-step" title={label} aria-label={label}>{children}</Link>;
}

/** Valeurs liées à leurs événements, les premières seulement ; le reste est au survol. Ces valeurs viennent d'échantillons
 * limités (10 comptes, 20 IP, événements conservés) : leur nombre n'est pas le total de l'alerte. */
function LinkedValues({ values, param, none, tags = {} }: { values: string[]; param: string; none: string; tags?: Record<string, string> }) {
  if (!values.length) return <span className="muted">{none}</span>;
  const rest = values.slice(VISIBLE_VALUES);
  return (
    <span className="summary-values">
      {values.slice(0, VISIBLE_VALUES).map((v) => (
        <span key={v}>
          <Link to={`/events?${param}=${encodeURIComponent(v)}`} className="mono">{v}</Link>
          {tags[v] && <span className="geo-tag">{tags[v]}</span>}
        </span>
      ))}
      {rest.length > 0 && <span className="muted small" title={rest.slice(0, 200).join("\n")}>et au moins {formatNumber(rest.length)} autres</span>}
    </span>
  );
}

/** L'essentiel, à la même place quelle que soit l'alerte : ce qui s'est passé, le verdict, qui, où, quand. */
function AlertSummary({ alert, qualification, users, ips }: {
  alert: Detail;
  qualification?: Qualification;
  users: string[];
  ips: string[];
}) {
  // Détection de l'outil (alertes reprises d'un outil : entité « … | rule.name=<détection> »)
  const detection = /rule\.name=(.+)$/.exec(alert.entity_key)?.[1] ?? "";
  const countries = Object.fromEntries(alert.events.filter((e) => e.source_ip && e.source_country).map((e) => [e.source_ip, e.source_country as string]));
  const hosts = allHosts(alert);
  const threat = threatState(alert.events);
  const ThreatIcon = threat?.tone === "stopped" ? ShieldCheck : threat?.tone === "partial" ? ShieldHalf : ShieldAlert;
  const tactics = [...new Set(alert.rule.mitre.flatMap((t) => t.tactics.map((x) => x.name)))];

  return (
    <section className="card alert-summary">
      <h2><Layers size={15} strokeWidth={2} /> Ce qui s'est passé</h2>
      {threat && (
        <div className={`threat-state threat-${threat.tone}`}>
          <ThreatIcon size={18} />
          <div>
            <strong>{threat.title}</strong> <span>{threat.detail}</span>
            <div className="muted small">D'après les détections conservées sur l'alerte (50 au plus) ; l'outil d'origine fait foi.</div>
          </div>
        </div>
      )}
      {detection && (
        <p className="summary-detection">
          <DetectionName name={detection} />
          <span className="small">
            <Link to={`/alerts?detection=${encodeURIComponent(detection)}`}>Toutes les alertes de cette détection</Link>
            {" · "}
            <Link to="/alerts?view=detections">Qualifier la détection</Link>
          </span>
        </p>
      )}
      {alert.rule.description && <p className="summary-lead">{alert.rule.description}</p>}
      {qualification && (
        <div className={`qualification verdict-box-${qualification.verdict}`}>
          <h3>
            Qualification automatique : <VerdictBadge verdict={qualification.verdict} label={qualification.label} />
          </h3>
          <ul>
            {qualification.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
          <p className="muted small">
            Verdict calculé à partir du motif d'échec, de l'historique des connexions réussies (30 jours) et du nombre de
            comptes visés. À confirmer : il oriente, il ne remplace pas votre analyse.
          </p>
        </div>
      )}
      <dl className="summary-facts">
        <div>
          <dt>Machines</dt>
          <dd>
            {hosts.length ? <HostChips hosts={hosts} visible={4} /> : <span className="muted">aucune identifiée</span>}
            {hosts.length === 1 && (hosts[0].owner || hosts[0].service) && (
              <div className="muted small">{[hosts[0].owner, hosts[0].service].filter(Boolean).join(" · ")}</div>
            )}
          </dd>
        </div>
        <div>
          <dt>Comptes</dt>
          <dd><LinkedValues values={users} param="user" none="aucun identifié" /></dd>
        </div>
        <div>
          <dt>Adresses IP</dt>
          <dd><LinkedValues values={ips} param="ip" none="aucune identifiée" tags={countries} /></dd>
        </div>
        <div>
          <dt>Activité</dt>
          <dd>
            <strong>{formatNumber(alert.count)}</strong> occurrence{alert.count > 1 ? "s" : ""} · dernière {timeAgo(alert.last_seen)}
            <div className="muted small">{formatDate(alert.first_seen)} → {formatDate(alert.last_seen)}</div>
          </dd>
        </div>
        <div>
          <dt>Source et règle</dt>
          <dd>
            <span className="summary-tools">
              {alert.modules.length ? alert.modules.map((m) => <ToolBadge key={m} module={m} />) : <ToolBadge />}
            </span>
            <div className="small" title={alert.rule_name}><span className="rule-chip">{alert.rule_id}</span> {alert.rule_name}</div>
          </dd>
        </div>
        {alert.rule.mitre.length > 0 && (
          <div>
            <dt>MITRE ATT&amp;CK</dt>
            <dd>
              <MitreTags techniques={alert.rule.mitre} />
              <div className="muted small">{tactics.join(" · ")}</div>
            </dd>
          </div>
        )}
      </dl>
      <details className="summary-more">
        <summary className="small">Pourquoi cette priorité, entité technique</summary>
        <dl className="followup-facts">
          {alert.priority !== undefined && (
            <>
              <dt>Priorité <span className="muted">({alert.priority} / 100)</span></dt>
              <dd><PriorityReasons reasons={alert.priority_reasons ?? []} /></dd>
            </>
          )}
          <dt>Entité</dt>
          <dd className="mono wrap-anywhere">{alert.entity_key}</dd>
        </dl>
      </details>
    </section>
  );
}

/** Statut, responsable, échéances, commentaire et historique : à portée de main pendant la lecture. */
function Treatment({ alert, editable, next, onDone }: { alert: Detail; editable: boolean; next: number | null; onDone: () => Promise<void> }) {
  const user = useUser();
  const navigate = useNavigate();
  const assignees = useAssignees();
  const [status, setStatus] = useState<AlertStatus | "">("");
  const [comment, setComment] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [waitingReason, setWaitingReason] = useState("utilisateur");
  const nextStatus = status || alert.status;
  const needsComment = CLOSED.includes(nextStatus) && nextStatus !== alert.status;
  const latest = alert.history[alert.history.length - 1];
  const nothingToSave = saving || (needsComment && !comment.trim()) || (!comment.trim() && nextStatus === alert.status);
  const formBody = () => ({
    ...(status && status !== alert.status ? { status } : {}),
    ...(status === "waiting" ? { waiting_reason: waitingReason } : {}),
    comment: comment.trim() || undefined,
  });

  /** `thenOpen` : alerte à ouvrir une fois la sauvegarde réussie ; en cas d'échec, on reste ici avec le message. */
  const save = async (body: Record<string, unknown>, thenOpen?: number) => {
    setSaving(true);
    setSaveError(null);
    try {
      await api(`/alerts/${alert.id}`, { method: "PATCH", body });
      if (thenOpen !== undefined) {
        navigate(`/alerts/${thenOpen}`);
        return;
      }
      setComment("");
      setStatus("");
      await onDone();
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card title="Traitement" icon={ClipboardCheck} className="alert-treatment">
      {alert.source_closure && <SourceClosureNote closure={alert.source_closure} />}
      <dl className="followup-facts">
        {!editable && (
          <>
            <dt>Responsable</dt>
            <dd>{alert.assignee ?? <span className="muted">non assignée</span>}</dd>
          </>
        )}
        <dt>Prise en charge</dt>
        <dd>
          {alert.acknowledged_at ? formatDate(alert.acknowledged_at) : <span className="muted">pas encore</span>}
          {alert.due?.ack_due && !alert.acknowledged_at && <span className="muted small"> · attendue avant le {formatDate(alert.due.ack_due)}</span>}
        </dd>
        {alert.due?.resolve_due && !CLOSED.includes(alert.status) && (
          <>
            <dt>Traitement attendu</dt>
            <dd>avant le {formatDate(alert.due.resolve_due)}</dd>
          </>
        )}
        {alert.status === "waiting" && alert.waiting && (
          <>
            <dt>En attente</dt>
            <dd>{waitingLabel(alert.waiting.reason)} <span className="muted small">depuis le {formatDate(alert.waiting.since)} ({alert.waiting.by})</span></dd>
          </>
        )}
        {alert.tool_state && !alert.source_closure && (
          <>
            <dt>Dans {alert.tool_state.tool}</dt>
            <dd>
              <ToolStateLine alert={alert} />
              {alert.tool_state.at && <span className="muted small">depuis le {formatDate(alert.tool_state.at)}</span>}
            </dd>
          </>
        )}
      </dl>
      {editable ? (
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            save(formBody());
          }}
        >
          <div className="treatment-fields">
            <label>
              Statut
              <select value={nextStatus} onChange={(e) => setStatus(e.target.value as AlertStatus)}>
                {(Object.keys(STATUS_LABEL) as AlertStatus[]).map((s) => (
                  <option key={s} value={s}>
                    {STATUS_LABEL[s]}
                  </option>
                ))}
              </select>
            </label>
            {nextStatus === "waiting" && status === "waiting" && (
              <label>
                Motif
                <select value={waitingReason} onChange={(e) => setWaitingReason(e.target.value)}>
                  {WAITING_REASONS.map((w) => <option key={w.value} value={w.value}>{w.label}</option>)}
                </select>
              </label>
            )}
            <label>
              Assignée à
              <select value={alert.assignee ?? ""} disabled={saving}
                onChange={(e) => save({ assignee: e.target.value || null, ...(e.target.value && alert.status === "new" ? { status: "in_progress" } : {}) })}>
                <option value="">— personne —</option>
                {assignees.map((a) => (
                  <option key={a.username} value={a.username}>
                    {a.display_name}{a.username === user?.username ? " (moi)" : ""}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {!CLOSED.includes(alert.status) && (
            <div className="quick-choices" role="group" aria-label="Clôture rapide">
              <span className="muted small">Clôturer :</span>
              {CLOSURES.map((c) => (
                <button key={c.status} type="button" className={`view-chip ${status === c.status ? "active" : ""}`} aria-pressed={status === c.status}
                  onClick={() => setStatus(status === c.status ? "" : c.status)}>
                  {STATUS_LABEL[c.status]}
                </button>
              ))}
            </div>
          )}
          <label>
            Commentaire {needsComment && <span className="required">(obligatoire pour clôturer)</span>}
            <textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={2} maxLength={4000} />
          </label>
          {needsComment && (
            <div className="quick-choices" role="group" aria-label="Commentaires types">
              {CLOSURES.find((c) => c.status === nextStatus)?.comments.map((text) => (
                <button key={text} type="button" className="view-chip" onClick={() => setComment((c) => (c.trim() ? `${c.trim()} ${text}` : text))}>
                  {text}
                </button>
              ))}
            </div>
          )}
          {saveError && <p className="form-error">{saveError}</p>}
          <div className="treatment-buttons">
            <button type="submit" className="primary" disabled={nothingToSave}>
              Enregistrer
            </button>
            {next !== null && (
              <button type="button" className="primary" disabled={nothingToSave} title="Enregistrer, puis ouvrir l'alerte suivante de la liste"
                onClick={() => save(formBody(), next)}>
                Enregistrer et suivante
              </button>
            )}
            {alert.assignee !== user?.username && (
              <button type="button" disabled={saving} onClick={() => save({ assignee: user?.username, status: alert.status === "new" ? "in_progress" : undefined })}>
                Me l'assigner
              </button>
            )}
          </div>
        </form>
      ) : (
        <p className="muted">Consultation seule (rôle lecteur).</p>
      )}
      <Fold title={`Historique (${alert.history.length})`} icon={History} className="rail-fold"
        hint={latest && `${timeAgo(latest.ts)} · ${latest.actor}`}>
        <ol className="timeline">
          {[...alert.history].reverse().map((h, i) => (
            <li key={i}>
              <time>{formatDate(h.ts)}</time> · <strong>{h.actor}</strong> · {ACTION_LABEL[h.action] ?? h.action}
              {h.detail && <div className="pre">{h.action === "status" ? STATUS_LABEL[h.detail as AlertStatus] ?? h.detail : h.detail}</div>}
            </li>
          ))}
        </ol>
      </Fold>
    </Card>
  );
}

/** Alerte de regroupement (anti-tempête) : les entités regroupées et le dégroupage. */
function GroupedEntities({ alert, grouped, editable, onDone }: {
  alert: Detail;
  grouped: [string, number][];
  editable: boolean;
  onDone: () => Promise<void>;
}) {
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fields = [...new Set(grouped.flatMap(([entity]) => Object.keys(entityParts(entity))))].filter((f) => !f.startsWith("*"));
  return (
    <Fold title={`Entités regroupées (${formatNumber(grouped.length)})`} icon={Layers} className="card" defaultOpen>
      <p className="muted small">
        Trop d'alertes distinctes en peu de temps pour cette règle : les nouvelles entités sont regroupées ici au lieu
        de créer une alerte (et une notification) chacune.
      </p>
      {editable && alert.status !== "resolved" && (
        <div className="row ungroup-row">
          <button type="button" disabled={saving} onClick={async () => {
            setSaving(true);
            setError(null);
            try {
              const r = await api<{ created: number }>(`/alerts/${alert.id}/ungroup`, { method: "POST" });
              window.alert(`${r.created} alerte(s) recréée(s), une par entité. Cette alerte de regroupement est clôturée.`);
              await onDone();
            } catch (err) {
              setError(err instanceof Error ? err.message : String(err));
            } finally {
              setSaving(false);
            }
          }}>
            Dégrouper : une alerte par entité
          </button>
          <span className="muted small">Sans nouvelle notification ; cette alerte sera clôturée.</span>
        </div>
      )}
      {error && <p className="form-error">{error}</p>}
      <div className="grouped-scroll">
        <table>
          <thead>
            <tr>
              {fields.map((f) => (
                <th key={f}>{FIELD_LABEL[f] ?? f}</th>
              ))}
              <th className="num">Occurrences</th>
            </tr>
          </thead>
          <tbody>
            {grouped.map(([entity, count]) => {
              const parts = entityParts(entity);
              return (
                <tr key={entity}>
                  {fields.map((f) => (
                    <td key={f} className={f === "host.name" || f === "source.ip" ? "mono" : ""}>
                      {SEARCHABLE[f] && parts[f] ? (
                        <Link to={`/events?${SEARCHABLE[f]}=${encodeURIComponent(parts[f])}`}>{parts[f]}</Link>
                      ) : f === "event.module" ? (
                        moduleLabel(parts[f] ?? "")
                      ) : (
                        parts[f] ?? "—"
                      )}
                    </td>
                  ))}
                  <td className="num">{formatNumber(count)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Fold>
  );
}
