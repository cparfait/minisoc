import { ExternalLink } from "lucide-react";
import { Siren } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { canEdit, useUser } from "../App";
import AIConversation from "../components/AIConversation";
import BlockPanel from "../components/BlockPanel";
import EventTable from "../components/EventTable";
import ExceptionFromAlert from "../components/ExceptionFromAlert";
import { OverdueBadge, ToolActions, ToolStateLine, WAITING_REASONS, useAssignees, waitingLabel } from "../components/Followup";
import { CategoryBadge, PriorityPill, PriorityReasons } from "../components/Priority";
import { SourceClosureNote } from "../components/SourceClosure";
import { DerivedDetails } from "../components/Risk";
import Triage from "../components/Triage";
import { ImpactedHosts } from "../components/Hosts";
import IncidentPicker, { IncidentBadge } from "../components/IncidentPicker";
import IsolationPanel from "../components/IsolationPanel";
import { Card, ErrorBanner, MitreTags, PageHeader, SeverityBadge, StatusBadge, VerdictBadge } from "../components/ui";
import { usePolling } from "../hooks";
import { ACTION_LABEL, STATUS_LABEL, formatDate, formatNumber, moduleLabel } from "../labels";
import type { AlertDetail as Detail, AlertStatus, Qualification } from "../types";

const CLOSED: AlertStatus[] = ["resolved", "false_positive"];
const SEARCHABLE: Record<string, string> = { "source.ip": "ip", "user.name": "user", "host.name": "host" };


export default function AlertDetail() {
  const { id } = useParams();
  const user = useUser();
  const { data: alert, error, reload } = usePolling(() => api<Detail>(`/alerts/${id}`), [id], 30000);
  const [status, setStatus] = useState<AlertStatus | "">("");
  const [comment, setComment] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [waitingReason, setWaitingReason] = useState("utilisateur");
  const assignees = useAssignees();

  if (!alert) return <ErrorBanner error={error} />;

  const editable = canEdit(user);
  const consoleName = alert.modules.length ? moduleLabel(alert.modules[0]) : "l'outil d'origine";
  // Détection de l'outil (alertes reprises d'un outil : entité « … | rule.name=<détection> »)
  const detection = /rule\.name=(.+)$/.exec(alert.entity_key)?.[1] ?? "";
  const nextStatus = status || alert.status;
  const needsComment = CLOSED.includes(nextStatus) && nextStatus !== alert.status;

  const save = async (body: Record<string, unknown>) => {
    setSaving(true);
    setSaveError(null);
    try {
      await api(`/alerts/${alert.id}`, { method: "PATCH", body });
      setComment("");
      setStatus("");
      await reload();
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const sampleIps = (alert.details.sample_ips as string[] | undefined) ?? [];
  const sampleUsers = (alert.details.sample_users as string[] | undefined) ?? [];
  const qualification = alert.details.qualification as Qualification | undefined;
  // IP candidates au blocage : entité, IP observées, entités regroupées (anti-tempête)
  const groupedIps = Object.keys((alert.details.entities as Record<string, number> | undefined) ?? {})
    .filter((k) => k.startsWith("source.ip=") && !k.includes(" | "))
    .map((k) => k.slice("source.ip=".length));
  const entityIp = alert.entity_key.startsWith("source.ip=") && !alert.entity_key.includes(" | ")
    ? [alert.entity_key.slice("source.ip=".length)] : [];
  const blockCandidates = [...new Set([...entityIp, ...((alert.details.sample_ips as string[] | undefined) ?? []), ...groupedIps])];
  const FIELD_LABEL: Record<string, string> = { "event.module": "Source", "host.name": "Machine", "rule.name": "Détection",
    "source.ip": "Adresse IP", "user.name": "Compte" };
  const grouped = Object.entries((alert.details.entities as Record<string, number> | undefined) ?? {}).sort(
    (a, b) => b[1] - a[1],
  );
  const groupedFields = [...new Set(grouped.flatMap(([entity]) => entity.split(" | ").map((p) => p.split("=", 2)[0])))]
    .filter((f) => f && !f.startsWith("*"));

  return (
    <>
      <PageHeader title={alert.title} icon={Siren}>
        <SeverityBadge severity={alert.severity} />
        <StatusBadge status={alert.status} />
        {alert.incident_id && <IncidentBadge id={alert.incident_id} />}
        {alert.reference && (
          <a className="button" href={alert.reference} target="_blank" rel="noopener noreferrer">
            Gérer dans {consoleName} <ExternalLink size={14} />
          </a>
        )}
      </PageHeader>
      <p className="muted breadcrumb">
        <Link to="/alerts">Alertes</Link> / n° {alert.id}
      </p>
      <ErrorBanner error={error} />

      <ImpactedHosts hosts={alert.hosts} events={alert.events} />
      <Triage events={alert.events} />
      <DerivedDetails details={alert.details} />

      {qualification && (
        <section className={`card qualification verdict-box-${qualification.verdict}`}>
          <h2>
            Qualification automatique : <VerdictBadge verdict={qualification.verdict} label={qualification.label} />
          </h2>
          <ul>
            {qualification.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
          <p className="muted small">
            Verdict calculé à partir du motif d'échec, de l'historique des connexions réussies (30 jours) et du nombre de
            comptes visés. À confirmer : il oriente, il ne remplace pas votre analyse.
          </p>
        </section>
      )}

      <div className="grid-2 detail">
        <Card title="Informations">
          <dl className="facts">
            {alert.priority !== undefined && (
              <>
                <dt>Priorité</dt>
                <dd>
                  <PriorityPill score={alert.priority} reasons={alert.priority_reasons} /> <span className="muted small">/ 100</span>
                  <PriorityReasons reasons={alert.priority_reasons ?? []} />
                </dd>
              </>
            )}
            {detection && (
              <>
                <dt>Détection</dt>
                <dd>
                  {detection} <CategoryBadge category={alert.category} />
                  <div className="small">
                    <Link to={`/alerts?detection=${encodeURIComponent(detection)}`}>Toutes les alertes de cette détection</Link>
                    {" · "}
                    <Link to="/alerts?view=detections">Qualifier la détection</Link>
                  </div>
                </dd>
              </>
            )}
            <dt>Règle</dt>
            <dd>
              {alert.rule_id} – {alert.rule_name}
            </dd>
            {alert.rule.mitre.length > 0 && (
              <>
                <dt>MITRE ATT&amp;CK</dt>
                <dd>
                  <MitreTags techniques={alert.rule.mitre} />
                  <div className="muted small">{[...new Set(alert.rule.mitre.flatMap((t) => t.tactics.map((x) => x.name)))].join(" · ")}</div>
                </dd>
              </>
            )}
            {alert.rule.description && (
              <>
                <dt>Description</dt>
                <dd>{alert.rule.description}</dd>
              </>
            )}
            <dt>Entité</dt>
            <dd className="mono">{alert.entity_key}</dd>
            <dt>Occurrences</dt>
            <dd>{formatNumber(alert.count)}</dd>
            <dt>Première détection</dt>
            <dd>{formatDate(alert.first_seen)}</dd>
            <dt>Dernière détection</dt>
            <dd>{formatDate(alert.last_seen)}</dd>
            <dt>Sources</dt>
            <dd>{alert.modules.map(moduleLabel).join(", ") || "—"}</dd>
            <dt>Assignée à</dt>
            <dd>{alert.assignee ?? "—"}</dd>
            {alert.reference && (
              <>
                <dt>Console d'origine</dt>
                <dd>
                  <a href={alert.reference} target="_blank" rel="noopener noreferrer">
                    Ouvrir dans {consoleName} <ExternalLink size={14} />
                  </a>
                </dd>
              </>
            )}
            {sampleIps.length > 0 && (
              <>
                <dt>IP observées</dt>
                <dd className="mono wrap">
                  {sampleIps.map((ip) => (
                    <Link key={ip} to={`/events?ip=${encodeURIComponent(ip)}`}>
                      {ip}
                    </Link>
                  ))}
                </dd>
              </>
            )}
            {sampleUsers.length > 0 && (
              <>
                <dt>Comptes visés</dt>
                <dd className="mono wrap">
                  {sampleUsers.map((u) => (
                    <Link key={u} to={`/events?user=${encodeURIComponent(u)}`}>
                      {u}
                    </Link>
                  ))}
                </dd>
              </>
            )}
          </dl>
        </Card>

        <Card title="Traitement">
          {alert.source_closure && <SourceClosureNote closure={alert.source_closure} />}
          <dl className="followup-facts">
            <dt>Responsable</dt>
            <dd>{alert.assignee ?? <span className="muted">non assignée</span>}</dd>
            <dt>Prise en charge</dt>
            <dd>
              {alert.acknowledged_at ? formatDate(alert.acknowledged_at) : <span className="muted">pas encore</span>}
              {alert.due?.ack_due && !alert.acknowledged_at && <span className="muted small"> · attendue avant le {formatDate(alert.due.ack_due)}</span>}
            </dd>
            {alert.due?.resolve_due && !CLOSED.includes(alert.status) && (
              <>
                <dt>Traitement attendu</dt>
                <dd>avant le {formatDate(alert.due.resolve_due)} <OverdueBadge alert={alert} /></dd>
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
                save({
                  ...(status && status !== alert.status ? { status } : {}),
                  ...(status === "waiting" ? { waiting_reason: waitingReason } : {}),
                  comment: comment.trim() || undefined,
                });
              }}
            >
              <div className="row followup-row">
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
                {alert.assignee !== user?.username && (
                  <button type="button" disabled={saving} onClick={() => save({ assignee: user?.username, status: alert.status === "new" ? "in_progress" : undefined })}>
                    Me l'assigner
                  </button>
                )}
              </div>
              <label>
                Commentaire {needsComment && <span className="required">(obligatoire pour clôturer)</span>}
                <textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={3} maxLength={4000} />
              </label>
              {saveError && <p className="form-error">{saveError}</p>}
              <button
                type="submit"
                className="primary"
                disabled={saving || (needsComment && !comment.trim()) || (!comment.trim() && nextStatus === alert.status)}
              >
                Enregistrer
              </button>
            </form>
          ) : (
            <p className="muted">Consultation seule (rôle lecteur).</p>
          )}
          <div className="incident-box">
            <h3>Incident</h3>
            {alert.incident_id ? (
              <p>
                Rattachée à l'<IncidentBadge id={alert.incident_id} /> : le traitement se suit dans l'incident.
              </p>
            ) : editable ? (
              <IncidentPicker alertIds={[alert.id]} defaultTitle={alert.title} onDone={reload} />
            ) : (
              <p className="muted">Aucun incident.</p>
            )}
          </div>
          <ToolActions alert={alert} />
          {editable && !["resolved", "false_positive"].includes(alert.status) && (
            <div className="exception-box">
              <ExceptionFromAlert alertId={alert.id} ruleId={alert.rule_id} entityKey={alert.entity_key} onDone={reload} />
            </div>
          )}
          <h3>Historique</h3>
          <ol className="timeline">
            {alert.history.map((h, i) => (
              <li key={i}>
                <time>{formatDate(h.ts)}</time> · <strong>{h.actor}</strong> · {ACTION_LABEL[h.action] ?? h.action}
                {h.detail && <div className="pre">{h.action === "status" ? STATUS_LABEL[h.detail as AlertStatus] ?? h.detail : h.detail}</div>}
              </li>
            ))}
          </ol>
        </Card>
      </div>

      {grouped.length > 0 && (
        <Card title={`Entités regroupées (${grouped.length})`}>
          <p className="muted small">
            Trop d'alertes distinctes en peu de temps pour cette règle : les nouvelles entités sont regroupées ici au lieu
            de créer une alerte (et une notification) chacune.
          </p>
          {editable && alert.status !== "resolved" && (
            <div className="row ungroup-row">
              <button type="button" disabled={saving} onClick={async () => {
                setSaving(true);
                setSaveError(null);
                try {
                  const r = await api<{ created: number }>(`/alerts/${alert.id}/ungroup`, { method: "POST" });
                  setSaveError(null);
                  window.alert(`${r.created} alerte(s) recréée(s), une par entité. Cette alerte de regroupement est clôturée.`);
                  reload();
                } catch (err) {
                  setSaveError(err instanceof Error ? err.message : String(err));
                } finally {
                  setSaving(false);
                }
              }}>
                Dégrouper : une alerte par entité
              </button>
              <span className="muted small">Sans nouvelle notification ; cette alerte sera clôturée.</span>
            </div>
          )}
          <table>
            <thead>
              <tr>
                {groupedFields.map((f) => (
                  <th key={f}>{FIELD_LABEL[f] ?? f}</th>
                ))}
                <th className="num">Occurrences</th>
              </tr>
            </thead>
            <tbody>
              {grouped.map(([entity, count]) => {
                const parts = Object.fromEntries(entity.split(" | ").map((p) => p.split("=", 2) as [string, string]));
                return (
                  <tr key={entity}>
                    {groupedFields.map((f) => (
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
        </Card>
      )}

      {editable && alert.modules.some((m) => m === "harfanglab" || m === "bitdefender") && (
        <Card title="Isoler le poste (EDR)">
          <IsolationPanel key={alert.id} alertId={alert.id} onDone={reload} />
        </Card>
      )}

      {editable && blockCandidates.length > 0 && (
        <Card title="Bloquer sur le pare-feu">
          <BlockPanel key={alert.id} alertId={alert.id} title={alert.title} candidates={blockCandidates} />
        </Card>
      )}

      {editable && (
        <Card title="Assistant IA">
          <AIConversation
            key={alert.id}
            path={`/ai/alerts/${alert.id}/analyze`}
            initialQuestion="Analyse cette alerte."
            placeholder="Question de suivi (ex. : comment bloquer ces IP sur le XGS ?)"
          />
        </Card>
      )}

      {alert.playbook && (
        <Card title="Fiche réflexe">
          {/* Affichée en texte brut : aucun HTML interprété */}
          <div className="pre playbook">{alert.playbook}</div>
        </Card>
      )}

      <Card title={`Événements liés (${alert.events.length})`}>
        <EventTable events={alert.events} />
      </Card>
    </>
  );
}
