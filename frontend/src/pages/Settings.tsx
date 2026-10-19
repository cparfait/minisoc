import { Settings as SettingsIcon } from "lucide-react";
import NotifyRouting from "../components/NotifyRouting";
import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Card, ErrorBanner, PageHeader } from "../components/ui";
import WallSettings from "../components/WallSettings";

type Kind = "text" | "secret" | "bool" | "int" | "pem" | "list" | "choice";
interface FieldDef {
  key: string;
  label: string;
  kind: Kind;
  help?: string;
  placeholder?: string;
  choices?: { value: string; label: string }[];
}

const LDAP_FIELDS: FieldDef[] = [
  { key: "ldap_enabled", label: "Activer l'authentification Active Directory", kind: "bool" },
  { key: "ldap_url", label: "Serveur LDAPS", kind: "text", placeholder: "ldaps://dc01.mairie.local:636",
    help: "Nom DNS du contrôleur de domaine tel qu'il figure dans son certificat (pas l'adresse IP). LDAP en clair refusé." },
  { key: "ldap_ca_cert", label: "Certificat de l'autorité de certification de l'AD (PEM)", kind: "pem",
    help: "Nécessaire si le certificat du DC est émis par votre PKI interne (AD CS). Le certificat est toujours vérifié." },
  { key: "ldap_bind_dn", label: "Compte de service (lecture seule)", kind: "text",
    placeholder: "CN=svc-minisoc,OU=Services,DC=mairie,DC=local", help: "Simple utilisateur du domaine, sans droit d'administration." },
  { key: "ldap_bind_password", label: "Mot de passe du compte de service", kind: "secret" },
  { key: "ldap_base_dn", label: "Base de recherche des utilisateurs", kind: "text", placeholder: "OU=Utilisateurs,DC=mairie,DC=local" },
  { key: "ldap_user_filter", label: "Filtre de recherche", kind: "text", help: "{username} est remplacé par l'identifiant saisi (échappé)." },
  { key: "ldap_group_admin", label: "Groupe AD → rôle Administrateur", kind: "text", placeholder: "CN=GG-MiniSOC-Admins,OU=Groupes,DC=mairie,DC=local" },
  { key: "ldap_group_analyst", label: "Groupe AD → rôle Analyste", kind: "text", placeholder: "CN=GG-MiniSOC-Analystes,OU=Groupes,DC=mairie,DC=local" },
  { key: "ldap_group_viewer", label: "Groupe AD → rôle Lecteur", kind: "text", placeholder: "CN=GG-MiniSOC-Lecteurs,OU=Groupes,DC=mairie,DC=local",
    help: "Groupes imbriqués pris en compte. Un compte AD sans aucun de ces groupes est refusé." },
  { key: "ldap_timeout", label: "Délai maximal (secondes)", kind: "int" },
];

const SMTP_FIELDS: FieldDef[] = [
  { key: "smtp_host", label: "Serveur SMTP", kind: "text", placeholder: "smtp.mairie.local ou <tenant>.mail.protection.outlook.com" },
  { key: "smtp_port", label: "Port", kind: "int", help: "587 (STARTTLS), 465 (TLS direct) ou 25 (relais)." },
  { key: "smtp_security", label: "Chiffrement", kind: "choice", choices: [
    { value: "starttls", label: "STARTTLS obligatoire (certificat vérifié)" },
    { value: "ssl", label: "TLS direct, port 465 (certificat vérifié)" },
    { value: "none", label: "Aucun — relais interne uniquement (déconseillé)" },
  ] },
  { key: "smtp_user", label: "Utilisateur (facultatif)", kind: "text", help: "Laisser vide pour un relais sans authentification." },
  { key: "smtp_password", label: "Mot de passe", kind: "secret" },
  { key: "smtp_from", label: "Expéditeur", kind: "text", placeholder: "minisoc@mairie.fr" },
  { key: "smtp_to", label: "Destinataires des alertes", kind: "list", placeholder: "admin.reseau@mairie.fr, dsi@mairie.fr" },
  { key: "smtp_ca_cert", label: "Certificat d'autorité du serveur SMTP (PEM, facultatif)", kind: "pem" },
];

const DETECTION_FIELDS: FieldDef[] = [
  { key: "dns_server", label: "Serveur DNS interne (Active Directory)", kind: "text", placeholder: "192.168.2.9",
    help: "Affiche le nom des machines à côté des adresses internes (résolution inverse). Seules les adresses privées sont résolues, auprès de ce seul serveur." },
  { key: "home_countries", label: "Pays habituels des connexions (codes ISO)", kind: "list", placeholder: "FR, BE",
    help: "Une connexion depuis un autre pays est signalée dans la qualification des alertes VPN (base GeoIP requise)." },
  { key: "threat_feeds_enabled", label: "Veille automatique : CISA KEV et CERT-FR (accès Internet sortant requis)", kind: "bool" },
  { key: "accounts_ad_sync", label: "Comptes sensibles : lire chaque heure les administrateurs et comptes de service dans l'AD", kind: "bool",
    help: "Administrateurs : attribut adminCount=1 (membres actuels ou anciens des groupes protégés). Comptes de service : SPN déclaré, gMSA/MSA. Utilise le compte de service LDAPS de l'onglet Annuaire AD." },
  { key: "accounts_admin_patterns", label: "Comptes administrateurs : motifs de noms en plus de l'AD", kind: "list",
    placeholder: "adm-*, admin_*", help: "Joker * accepté, sans distinction de casse. Ex. : adm-* pour les comptes d'administration séparés." },
  { key: "accounts_service_patterns", label: "Comptes de service : motifs de noms en plus de l'AD", kind: "list",
    placeholder: "svc*, sa_*", help: "Les comptes machine (se terminant par $) ne sont jamais concernés par les motifs." },
  { key: "risk_threshold", label: "Score de risque : seuil d'alerte (points sur 7 jours)", kind: "int",
    help: "Défaut 60 : par exemple une détection haute et une critique, ou trois hautes avec deux tactiques MITRE. Au double du seuil, l'alerte devient critique." },
  { key: "disk_alert_percent", label: "Disques de la VM Mini-SOC : seuil d'alerte d'occupation (%)", kind: "int",
    help: "Défaut 85 : alerte UC-63 quand une partition (/, /var/log, disque de données) dépasse ce seuil, en espace ou en inodes ; haute à partir de 95 %. État dans Statistiques › Santé des sources." },
  { key: "chain_auto_incident", label: "Chaîne d'attaque (3 tactiques MITRE en 24 h) : ouvrir automatiquement un incident", kind: "bool" },
  { key: "decoy_accounts", label: "Leurres : comptes jamais utilisés", kind: "list", placeholder: "adm-sauvegarde, svc-sql-old",
    help: "Toute connexion, demande de ticket Kerberos ou modification de ces comptes crée une alerte critique (UC-45). Voir docs/05-leurres.md pour les créer." },
  { key: "decoy_paths", label: "Leurres : dossiers ou fichiers pièges", kind: "list", placeholder: "\\SRV-FICHIERS\Paie_2026, Mots de passe.xlsx",
    help: "Correspondance dans le chemin des accès aux fichiers (audit des accès activé sur le dossier)." },
  { key: "decoy_hosts", label: "Leurres : machines sans usage (nom ou adresse IP)", kind: "list", placeholder: "PC-LEURRE, 10.0.0.99" },
  { key: "decoy_tokens", label: "Leurres : chaînes secrètes (faux mots de passe, fausses clés), 8 caractères au moins", kind: "list",
    help: "Leur apparition dans un journal (tentative de connexion, ligne de commande) prouve qu'elles ont été trouvées. La valeur n'est jamais recopiée dans l'alerte." },
  { key: "dns_trusted_domains", label: "DNS : domaines de confiance (exclus des règles tunnel et DGA)", kind: "list",
    help: "Éditeurs, antivirus, CDN dont les noms techniques ressemblent à des tunnels ou à des noms générés." },
];

const FOLLOWUP_FIELDS: FieldDef[] = [
  { key: "sla_ack_critical", label: "Critique : prise en charge sous (heures)", kind: "int" },
  { key: "sla_resolve_critical", label: "Critique : traitement sous (jours)", kind: "int" },
  { key: "sla_ack_high", label: "Haute : prise en charge sous (heures)", kind: "int" },
  { key: "sla_resolve_high", label: "Haute : traitement sous (jours)", kind: "int" },
  { key: "sla_ack_medium", label: "Moyenne : prise en charge sous (heures)", kind: "int" },
  { key: "sla_resolve_medium", label: "Moyenne : traitement sous (jours)", kind: "int" },
  { key: "sla_ack_low", label: "Faible : prise en charge sous (heures)", kind: "int" },
  { key: "sla_resolve_low", label: "Faible : traitement sous (jours)", kind: "int",
    help: "Prise en charge : l'alerte quitte « nouvelle » ou reçoit un responsable. Les échéances sont suspendues tant que l'alerte est « en attente »." },
  { key: "assign_notify", label: "Prévenir par e-mail la personne à qui une alerte est assignée (adresse du compte requise)", kind: "bool" },
];

const RETENTION_FIELDS: FieldDef[] = [
  { key: "events_retention_days", label: "Conservation des événements (jours)", kind: "int",
    help: "Recompressés après 7 jours, supprimés au-delà de cette durée (365 par défaut, RGPD)." },
  { key: "alerts_retention_days", label: "Conservation des alertes clôturées (jours)", kind: "int",
    help: "3 ans par défaut, 1 an minimum. Le journal d'audit n'est jamais purgé." },
];

const NOTIFY_FIELDS: FieldDef[] = [
  { key: "teams_webhook_url", label: "Webhook Teams (flux Workflows)", kind: "secret",
    help: "Teams > canal > Workflows > « Publier dans un canal lorsqu'une requête webhook est reçue »." },
  { key: "ntfy_url", label: "Serveur ntfy (notifications mobiles)", kind: "text", placeholder: "https://ntfy.sh ou votre instance" },
  { key: "ntfy_topic", label: "Sujet ntfy", kind: "text", help: "Choisir un nom long et imprévisible : quiconque le connaît peut lire les messages sur ntfy.sh." },
  { key: "ntfy_token", label: "Jeton ntfy (facultatif)", kind: "secret" },
  { key: "escalation_enabled", label: "Relancer un second contact si une alerte grave n'est pas prise en charge", kind: "bool" },
  { key: "escalation_minutes", label: "Délai avant relance (minutes)", kind: "int" },
  { key: "escalation_min_severity", label: "Alertes concernées", kind: "choice", choices: [
    { value: "critical", label: "Critiques uniquement" },
    { value: "high", label: "Hautes et critiques" },
  ] },
  { key: "escalation_to", label: "Second contact (e-mails)", kind: "list", placeholder: "dsi@mairie.fr, astreinte@mairie.fr" },
  { key: "escalation_ntfy_topic", label: "Sujet ntfy du second contact (facultatif)", kind: "text" },
  { key: "digest_enabled", label: "Envoyer un résumé quotidien par e-mail", kind: "bool" },
  { key: "digest_hour", label: "Heure d'envoi (0-23)", kind: "int" },
  { key: "digest_to", label: "Destinataires du résumé", kind: "list", help: "Vide = destinataires des alertes (onglet Messagerie)." },
  { key: "report_monthly_enabled", label: "Envoyer le rapport mensuel le 1er du mois (même heure et mêmes destinataires que le résumé)", kind: "bool" },
];

type Values = Record<string, unknown>;

function SettingsForm({ group, fields, children }: { group: string; fields: FieldDef[]; children?: (saved: boolean) => React.ReactNode }) {
  const [values, setValues] = useState<Values>({});
  const [secretsSet, setSecretsSet] = useState<Record<string, boolean>>({});
  const [form, setForm] = useState<Values>({});
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const res = await api<{ values: Values }>(`/admin/settings/${group}`);
    const plain: Values = {};
    const secrets: Record<string, boolean> = {};
    for (const f of fields) {
      const v = res.values[f.key];
      if (f.kind === "secret") secrets[f.key] = Boolean((v as { set?: boolean })?.set);
      else plain[f.key] = f.kind === "list" ? ((v as string[]) ?? []).join(", ") : v;
    }
    setValues(plain);
    setSecretsSet(secrets);
    setForm({ ...plain, ...Object.fromEntries(fields.filter((f) => f.kind === "secret").map((f) => [f.key, ""])) });
  };
  useEffect(() => {
    load().catch((e) => setMessage({ ok: false, text: String(e) }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [group]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    const changes: Values = {};
    for (const f of fields) {
      if (f.kind === "secret") {
        if (form[f.key]) changes[f.key] = form[f.key];
      } else if (form[f.key] !== values[f.key]) {
        changes[f.key] = form[f.key];
      }
    }
    try {
      const res = await api<{ changed: string[] }>(`/admin/settings/${group}`, { method: "PUT", body: changes });
      setMessage({ ok: true, text: res.changed.length ? `Enregistré (${res.changed.length} paramètre(s) modifié(s)).` : "Aucune modification." });
      await load();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  const set = (key: string, value: unknown) => setForm({ ...form, [key]: value });
  const dirty = fields.some((f) => (f.kind === "secret" ? Boolean(form[f.key]) : form[f.key] !== values[f.key]));

  return (
    <>
      <form className="settings-form" onSubmit={submit}>
        {fields.map((f) => (
          <div key={f.key} className={`settings-field ${f.kind === "pem" ? "wide" : ""}`}>
            {f.kind === "bool" ? (
              <label className="checkbox">
                <input type="checkbox" checked={Boolean(form[f.key])} onChange={(e) => set(f.key, e.target.checked)} />
                {f.label}
              </label>
            ) : (
              <label>
                {f.label}
                {f.kind === "secret" && secretsSet[f.key] && <span className="badge status-resolved"> défini</span>}
                {f.kind === "pem" ? (
                  <textarea rows={4} className="mono" value={String(form[f.key] ?? "")} onChange={(e) => set(f.key, e.target.value)}
                    placeholder="-----BEGIN CERTIFICATE-----" />
                ) : f.kind === "choice" ? (
                  <select value={String(form[f.key] ?? "")} onChange={(e) => set(f.key, e.target.value)}>
                    {f.choices?.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
                  </select>
                ) : (
                  <input
                    type={f.kind === "secret" ? "password" : f.kind === "int" ? "number" : "text"}
                    value={String(form[f.key] ?? "")}
                    onChange={(e) => set(f.key, f.kind === "int" ? Number(e.target.value) : e.target.value)}
                    placeholder={f.kind === "secret" ? (secretsSet[f.key] ? "laisser vide pour ne pas changer" : "") : f.placeholder}
                    autoComplete={f.kind === "secret" ? "new-password" : "off"}
                    className={f.key.includes("_dn") || f.key.includes("group") || f.key === "ldap_url" ? "mono" : ""}
                  />
                )}
              </label>
            )}
            {f.help && <small className="muted">{f.help}</small>}
          </div>
        ))}
        <div className="settings-actions">
          <button type="submit" className="primary" disabled={busy || !dirty}>Enregistrer</button>
          {message && <span className={message.ok ? "text-good" : "form-error"}>{message.text}</span>}
        </div>
      </form>
      {children?.(!dirty)}
    </>
  );
}

function LdapTest({ saved }: { saved: boolean }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<{ ok: boolean; steps: { step: string; ok: boolean; detail: string }[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      setResult(await api("/admin/settings/ldap/test", { method: "POST", body: { username, password } }));
    } catch (err) {
      setResult({ ok: false, steps: [{ step: "Test", ok: false, detail: String(err) }] });
    } finally {
      setPassword("");
      setBusy(false);
    }
  };
  return (
    <form className="test-box" onSubmit={run}>
      <h3>Tester la connexion</h3>
      <p className="muted small">Teste les paramètres enregistrés. Facultatif : un compte AD pour vérifier son rôle (aucune session n'est créée).</p>
      <div className="row">
        <input placeholder="Identifiant à tester (facultatif)" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
        <input type="password" placeholder="Mot de passe" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
        <button type="submit" disabled={busy || !saved}>{busy ? "Test…" : "Tester"}</button>
      </div>
      {!saved && <p className="muted small">Enregistrez d'abord les modifications.</p>}
      {result && (
        <ul className="test-steps">
          {result.steps.map((s, i) => (
            <li key={i} className={s.ok ? "text-good" : "text-bad"}>
              {s.ok ? "✔" : "✘"} {s.step}
              {s.detail && <div className="muted small mono">{s.detail}</div>}
            </li>
          ))}
        </ul>
      )}
    </form>
  );
}

function SmtpTest({ saved }: { saved: boolean }) {
  const [to, setTo] = useState("");
  const [result, setResult] = useState<{ ok: boolean; detail: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      setResult(await api("/admin/settings/smtp/test", { method: "POST", body: { to } }));
    } catch (err) {
      setResult({ ok: false, detail: String(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="test-box" onSubmit={run}>
      <h3>Envoyer un e-mail de test</h3>
      <div className="row">
        <input placeholder="Destinataire (vide = destinataires des alertes)" value={to} onChange={(e) => setTo(e.target.value)} />
        <button type="submit" disabled={busy || !saved}>{busy ? "Envoi…" : "Envoyer"}</button>
      </div>
      {result && <p className={result.ok ? "text-good" : "text-bad"}>{result.detail}</p>}
    </form>
  );
}

interface TestResult {
  ok: boolean;
  detail: string;
  note?: string;
  results?: { channel: string; label: string; ok: boolean; detail: string }[];
}

/** Tests des notifications, en tête de l'onglet : chaque canal, puis le routage complet d'une sévérité. */
function NotifyTester() {
  const [result, setResult] = useState<TestResult | null>(null);
  const [busy, setBusy] = useState("");
  const [severity, setSeverity] = useState("critical");
  const run = async (label: string, path: string, body: unknown) => {
    setBusy(label);
    setResult(null);
    try {
      setResult(await api<TestResult>(path, { method: "POST", body }));
    } catch (err) {
      setResult({ ok: false, detail: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy("");
    }
  };
  const channel = (id: string, label: string) => (
    <button type="button" disabled={!!busy} onClick={() => run(id, "/admin/settings/notify/test", { channel: id })}>
      {busy === id ? "Envoi…" : label}
    </button>
  );
  return (
    <div className="test-box notify-tester">
      <h3>Tester les notifications</h3>
      <p className="muted small">Les tests utilisent les réglages <strong>enregistrés</strong> (enregistrez d'abord vos modifications).</p>
      <div className="row">
        {channel("email", "E-mail de test")}
        {channel("teams", "Message Teams de test")}
        {channel("ntfy", "Notification mobile de test")}
        <button type="button" disabled={!!busy} onClick={() => run("digest", "/admin/digest/send", { to: "" })}>
          {busy === "digest" ? "Envoi…" : "Envoyer le résumé maintenant"}
        </button>
      </div>
      <div className="row">
        <label className="inline">
          Simuler une alerte
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="critical">critique</option>
            <option value="high">haute</option>
            <option value="medium">moyenne</option>
            <option value="low">faible</option>
          </select>
        </label>
        <button type="button" className="primary" disabled={!!busy} onClick={() => run("route", "/admin/settings/notify/test-route", { severity })}>
          {busy === "route" ? "Envoi…" : "Tester le routage"}
        </button>
        <span className="muted small">envoie sur tous les canaux prévus pour cette sévérité</span>
      </div>
      {result && (
        <div className="notify-result">
          <p className={result.ok ? "text-good" : "text-bad"}>{result.detail}</p>
          {result.results && result.results.length > 0 && (
            <ul className="test-steps">
              {result.results.map((r) => (
                <li key={r.channel} className={r.ok ? "text-good" : "text-bad"}>
                  {r.ok ? "✔" : "✘"} {r.label} : {r.detail}
                </li>
              ))}
            </ul>
          )}
          {result.note && <p className="muted small">{result.note}</p>}
        </div>
      )}
    </div>
  );
}

const TABS = [
  { id: "ldap", label: "Annuaire Active Directory" },
  { id: "detection", label: "Détection" },
  { id: "retention", label: "Conservation" },
  { id: "smtp", label: "Messagerie (SMTP)" },
  { id: "notify", label: "Notifications" },
  { id: "followup", label: "Suivi" },
  { id: "wall", label: "Écran mural" },
];

export default function Settings() {
  const [tab, setTab] = useState("ldap");
  return (
    <>
      <PageHeader title="Paramètres" icon={SettingsIcon} subtitle="Annuaire, messagerie, notifications, détection, conservation" />
      <p className="muted">
        Réglages de la plateforme. Les solutions raccordées (sources, CrowdSec, pare-feu, IA…) se configurent dans{" "}
        <Link to="/integrations">Intégrations</Link>.
      </p>
      <div className="segmented" role="tablist">
        {TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={tab === t.id} className={tab === t.id ? "active" : ""} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      <ErrorBanner error={null} />
      <Card className="settings-card">
        {tab === "ldap" && (
          <SettingsForm key="ldap" group="ldap" fields={LDAP_FIELDS}>
            {(saved) => <LdapTest saved={saved} />}
          </SettingsForm>
        )}
        {tab === "detection" && <SettingsForm key="detection" group="detection" fields={DETECTION_FIELDS} />}
        {tab === "retention" && <SettingsForm key="retention" group="retention" fields={RETENTION_FIELDS} />}
        {tab === "followup" && <SettingsForm key="followup" group="followup" fields={FOLLOWUP_FIELDS} />}
        {tab === "wall" && <WallSettings />}
        {tab === "notify" && <NotifyTester />}
        {tab === "notify" && <NotifyRouting />}
        {tab === "notify" && <SettingsForm key="notify" group="notify" fields={NOTIFY_FIELDS} />}
        {tab === "smtp" && (
          <SettingsForm key="smtp" group="smtp" fields={SMTP_FIELDS}>
            {(saved) => <SmtpTest saved={saved} />}
          </SettingsForm>
        )}
      </Card>
    </>
  );
}
