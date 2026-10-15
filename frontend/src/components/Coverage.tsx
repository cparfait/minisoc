import { RefreshCw, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { canEdit, useUser } from "../App";
import { usePolling } from "../hooks";
import { timeAgo } from "../labels";
import { Card } from "./ui";

interface RuleResult {
  missing: number;
  raised: number;
  resolved: number;
}

interface CoverageStatus {
  coverage: {
    at: string;
    machines: number;
    errors: string[];
    antivirus_checked: boolean;
    edr_checked: boolean;
    "UC-58"?: RuleResult | null;
    "UC-59"?: RuleResult | null;
  } | null;
  identities: {
    users?: { at: string; aliases: number; accounts: number; error: string };
    hosts?: { at: string; addresses: number };
  };
}

function Gap({ label, rule, result, checked }: { label: string; rule: string; result?: RuleResult | null; checked: boolean }) {
  if (!checked || !result) {
    return (
      <li>
        <strong>{label}</strong> <span className="muted small">: non vérifié (console non lue en entier)</span>
      </li>
    );
  }
  return (
    <li>
      <strong>{label}</strong> :{" "}
      {result.missing === 0 ? (
        <span>aucune machine en service sans protection</span>
      ) : (
        <Link to={`/alerts?rule_id=${rule}`}>
          {result.missing} machine{result.missing > 1 ? "s" : ""} sans protection
        </Link>
      )}
      <span className="muted small"> · alerte après 24 h de constat</span>
    </li>
  );
}

/** Veille : couverture antivirus (GravityZone) et EDR (HarfangLab) des machines en service, tables d'identités. */
export default function Coverage() {
  const user = useUser();
  const [queued, setQueued] = useState(false);
  const { data } = usePolling(() => api<CoverageStatus>("/coverage"), [], 60000);
  const cov = data?.coverage;
  const ids = data?.identities;
  const run = async () => {
    await api("/coverage/run", { method: "POST" });
    setQueued(true);
  };
  return (
    <Card title="Couverture antivirus et EDR" icon={ShieldCheck}>
      {!cov ? (
        <p className="muted">Première vérification quelques minutes après le démarrage, puis chaque heure.</p>
      ) : (
        <>
          <p className="small">
            {cov.machines} machine(s) Windows ou macOS en service (NinjaOne, agents HarfangLab) · vérifié {timeAgo(cov.at)}
          </p>
          <ul className="plain-list">
            <Gap label="Antivirus Bitdefender" rule="UC-58" result={cov["UC-58"]} checked={cov.antivirus_checked} />
            <Gap label="EDR HarfangLab" rule="UC-59" result={cov["UC-59"]} checked={cov.edr_checked} />
          </ul>
          {cov.errors.map((e) => (
            <p key={e} className="small coverage-error">{e}</p>
          ))}
        </>
      )}
      {ids && (ids.users || ids.hosts) && (
        <p className="muted small">
          Identités rapprochées :{" "}
          {ids.users ? `${ids.users.aliases} formes de noms de comptes (UPN, messagerie, nom affiché) pour ${ids.users.accounts} comptes de l'annuaire` : "annuaire non lu"}
          {ids.hosts && ` · ${ids.hosts.addresses} adresses IP rattachées à une machine`}
          {ids.users?.error && ` · ${ids.users.error}`}
        </p>
      )}
      {canEdit(user) && (
        <button type="button" className="ghost small" onClick={run} disabled={queued}>
          <RefreshCw size={14} /> {queued ? "Vérification demandée" : "Vérifier maintenant"}
        </button>
      )}
    </Card>
  );
}
