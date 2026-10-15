import { ArrowLeft, Fingerprint, Lock } from "lucide-react";
import { useState, type FormEvent } from "react";
import { ApiError, api } from "../api";
import type { User } from "../types";

type Step = { kind: "password" } | { kind: "totp" } | { kind: "enroll"; qr: string; secret: string };

/** Boucle d'authentification : mot de passe (local ou AD) → code TOTP (ou enrôlement du MFA) → session.
 * Page volontairement neutre : rien sur les outils surveillés, les règles ni l'annuaire (repérage). */
export default function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const [step, setStep] = useState<Step>({ kind: "password" });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const restart = (message?: string) => {
    setStep({ kind: "password" });
    setPassword("");
    setCode("");
    setError(message ?? null);
  };

  const submitPassword = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ step: "totp" } | { step: "enroll"; qr: string; secret: string }>("/auth/login", {
        method: "POST",
        body: { username, password },
      });
      setPassword(""); // le mot de passe ne reste pas en mémoire au-delà de l'étape 1
      setStep(res.step === "enroll" ? { kind: "enroll", qr: res.qr, secret: res.secret } : { kind: "totp" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Connexion impossible");
    } finally {
      setBusy(false);
    }
  };

  const submitCode = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onLogin(await api<User>("/auth/verify", { method: "POST", body: { code } }));
    } catch (err) {
      setCode("");
      if (err instanceof ApiError && err.message.startsWith("Étape expirée")) restart(err.message);
      else setError(err instanceof Error ? err.message : "Code refusé");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <div className="login-panel">
      <div className="login-card">
        <div className="brand">
          <img src="/favicon.svg" alt="" width={32} height={32} />
          <span>Mini-SOC</span>
        </div>
        <h2>{step.kind === "password" ? "Connexion" : step.kind === "enroll" ? "Double authentification" : "Vérification"}</h2>

        {step.kind === "password" && (
          <form onSubmit={submitPassword} className="stack">
            <label>
              Identifiant
              <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required autoFocus />
            </label>
            <label>
              Mot de passe
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
            </label>
            {error && <p className="form-error" role="alert">{error}</p>}
            <button type="submit" className="primary" disabled={busy}>
              {busy ? "Vérification…" : "Continuer"}
            </button>
          </form>
        )}

        {step.kind !== "password" && (
          <form onSubmit={submitCode} className="stack">
            {step.kind === "enroll" ? (
              <>
                <p className="login-help">
                  <strong>Première connexion : activez la double authentification.</strong> Scannez ce QR code avec une
                  application d'authentification (Microsoft Authenticator, FreeOTP…), puis saisissez le code affiché.
                </p>
                <img src={step.qr} alt="QR code d'enrôlement de la double authentification" className="login-qr" />
                <details className="small muted">
                  <summary>Saisie manuelle de la clé</summary>
                  <code className="mono wrap-anywhere">{step.secret}</code>
                </details>
              </>
            ) : (
              <p className="login-help">Saisissez le code à 6 chiffres de votre application d'authentification.</p>
            )}
            <label className="login-code">
              Code à 6 chiffres
              <input
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="\d{6}"
                placeholder="123456"
                required
                autoFocus
              />
            </label>
            {error && <p className="form-error" role="alert">{error}</p>}
            <button type="submit" className="primary" disabled={busy || code.length !== 6}>
              {busy ? "Vérification…" : step.kind === "enroll" ? "Activer et se connecter" : "Se connecter"}
            </button>
            <button type="button" className="link" onClick={() => restart()}>
              <ArrowLeft size={15} /> Changer d'identifiant
            </button>
          </form>
        )}
        <p className="login-secure">
          {step.kind === "password" ? <Lock size={13} /> : <Fingerprint size={13} />}
          Accès réservé · connexions journalisées
        </p>
      </div>
      </div>
    </div>
  );
}
