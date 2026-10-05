export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type AlertStatus = "new" | "in_progress" | "waiting" | "resolved" | "false_positive";

export interface User {
  username: string;
  role: "admin" | "analyst" | "viewer";
  display_name?: string;
  auth_source?: "local" | "ldap";
}

export type Verdict = "attack" | "suspicious" | "benign";

export interface Qualification {
  verdict: Verdict;
  label: string;
  reasons: string[];
  severity: number | null;
}

export interface ImpactedHost {
  name: string;
  count: number;
  rules: string[];
  /** Inventaire : criticité, propriétaire et service de la machine */
  criticality?: "low" | "normal" | "high" | "vital";
  owner?: string;
  service?: string;
}

/** Clôture constatée dans l'outil d'origine (synchronisation des statuts). */
export interface SourceClosure {
  tool: string;
  status: string;
  label: string;
  by: string;
  at: string;
  observed: boolean;
  sources: number;
  synced_at: string;
}

/** Raison du score de priorité (points ajoutés ou retirés). */
export interface PriorityReason {
  label: string;
  points: number;
}

export type DetectionCategory = "threat" | "hygiene" | "info";

/** Une détection d'outil et ses alertes ouvertes (vue « Par détection »). */
export interface DetectionTopic {
  module: string;
  detection: string;
  category: DetectionCategory;
  profile: { category: DetectionCategory; severity: Severity | null; note: string; author: string; updated_at: string | null } | null;
  suggestion: { category: DetectionCategory; severity: Severity | null; why: string } | null;
  alerts: number;
  occurrences: number;
  machines: number;
  servers: number;
  widespread: boolean;
  hosts: ImpactedHost[];
  severity: Severity | null;
  tool_severity: Severity | null;
  first_seen: string | null;
  last_seen: string | null;
}

/** État lu dans l'outil d'origine (le Mini-SOC ne modifie jamais les outils). */
export interface ToolState {
  tool: string;
  status: string;
  label: string;
  by: string;
  at: string;
  open: number;
  total: number;
  checked_at?: string;
}

export interface Alert {
  hosts: ImpactedHost[];
  tool_state?: ToolState | null;
  waiting?: { reason: string; since: string; by: string } | null;
  acknowledged_at?: string | null;
  due?: { ack_due: string | null; resolve_due: string | null; overdue: "ack" | "resolve" | null } | null;
  priority?: number;
  priority_reasons?: PriorityReason[];
  category?: DetectionCategory | null;
  source_closure?: SourceClosure | null;
  id: number;
  verdict: Verdict | null;
  verdict_label: string | null;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  title: string;
  entity_key: string;
  status: AlertStatus;
  assignee: string | null;
  first_seen: string;
  last_seen: string;
  count: number;
  metric: number;
  modules: string[];
  reference: string;
  incident_id: number | null;
  notified_at: string | null;
  created_at: string | null;
}

export interface HistoryEntry {
  ts: string;
  actor: string;
  action: string;
  detail: string;
}

export interface EventRow {
  reference?: string;
  ts: string;
  event_id: string;
  module: string;
  kind: string;
  category: string;
  action: string;
  outcome: string;
  severity: number;
  source_ip: string;
  source_country?: string;
  source_as?: string;
  intel?: string;
  destination_ip: string;
  user_name: string;
  host_name: string;
  network_service: string;
  rule_name: string;
  threat_name: string;
  observer: string;
  message: string;
  raw: string;
}

export interface AlertDetail extends Alert {
  details: Record<string, unknown>;
  rule: { description: string; type: string; mitre: MitreTechnique[] };
  playbook: string;
  history: HistoryEntry[];
  events: EventRow[];
}

export interface Source {
  module: string;
  last_seen: string | null;
  max_silence_minutes: number | null;
  monitored: boolean;
  status: "ok" | "silent" | "unknown";
}

export interface Overview {
  open_by_severity: Record<Severity, number>;
  new_24h: number;
  trend: ({ day: string } & Record<Severity, number>)[];
  top_rules: { rule_id: string; rule_name: string; count: number }[];
  top_attackers: { ip: string; failures: number; users: number; sample_users: string[]; country?: string; asn?: string; intel?: string }[];
  failures_by_country: { country: string; failures: number; ips: number }[];
  auth_failures_hourly: { hour: string; count: number }[];
  events_by_module: { module: string; count: number }[];
  sources: Source[];
  clickhouse_error?: boolean;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactics: { id: string; name: string }[];
  url: string;
}

export interface Rule {
  id: string;
  name: string;
  type: string;
  severity: string;
  description: string;
  enabled: boolean;
  window: string | null;
  condition: string | null;
  group_by: string[];
  file: string;
  mitre: MitreTechnique[];
}

export interface RuleExceptionItem {
  id: number;
  rule_id: string;
  field: string;
  value: string;
  reason: string;
  author: string;
  expires_at: string;
  created_at: string | null;
  active: boolean;
}

export interface Incident {
  id: number;
  title: string;
  description: string;
  category: string;
  severity: Severity;
  status: "open" | "investigating" | "contained" | "closed";
  owner: string | null;
  created_by: string;
  personal_data: boolean;
  conclusion: string;
  alert_count: number;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}
