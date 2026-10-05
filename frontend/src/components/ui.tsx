import { CircleAlert, Inbox, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { SEVERITY_LABEL, STATUS_LABEL } from "../labels";
import type { AlertStatus, MitreTechnique, Severity, Verdict } from "../types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{SEVERITY_LABEL[severity]}</span>;
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return <span className={`badge status-${status}`}>{STATUS_LABEL[status]}</span>;
}

export function VerdictBadge({ verdict, label }: { verdict: Verdict | null; label: string | null }) {
  if (!verdict) return null;
  return <span className={`badge verdict-${verdict}`}>{label}</span>;
}

export function PageHeader({ title, subtitle, icon: Icon, children }: {
  title: string;
  subtitle?: ReactNode;
  icon?: LucideIcon;
  children?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div className="page-title">
        {Icon && (
          <span className="page-icon">
            <Icon size={21} strokeWidth={1.9} />
          </span>
        )}
        <div>
          <h1>{title}</h1>
          {subtitle && <p className="page-subtitle">{subtitle}</p>}
        </div>
      </div>
      {children && <div className="page-actions">{children}</div>}
    </header>
  );
}

export function ErrorBanner({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div className="error-banner" role="alert">
      <CircleAlert size={18} />
      <span>{error}</span>
    </div>
  );
}

export function Card({ title, icon: Icon, children, className = "" }: {
  title?: string;
  icon?: LucideIcon;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {title && (
        <h2>
          {Icon && <Icon size={15} strokeWidth={2} />}
          {title}
        </h2>
      )}
      {children}
    </section>
  );
}

export function Empty({ children, icon: Icon = Inbox }: { children: ReactNode; icon?: LucideIcon }) {
  return (
    <p className="empty">
      <Icon size={18} strokeWidth={1.8} />
      <span>{children}</span>
    </p>
  );
}

/** Techniques MITRE ATT&CK, avec lien vers la fiche officielle. */
export function MitreTags({ techniques }: { techniques: MitreTechnique[] }) {
  if (!techniques.length) return null;
  return (
    <span className="mitre-tags">
      {techniques.map((t) => (
        <a key={t.id} href={t.url} target="_blank" rel="noopener noreferrer" className="mitre-tag"
          title={`${t.name}${t.tactics.length ? " — " + t.tactics.map((x) => x.name).join(", ") : ""}`}>
          {t.id}
        </a>
      ))}
    </span>
  );
}
