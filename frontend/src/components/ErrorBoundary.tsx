import { Component, type ErrorInfo, type ReactNode } from "react";
import { ErrorBanner } from "./ui";

/**
 * Garde-fou d'écran : une erreur de rendu reste limitée à la page concernée, le menu reste disponible.
 * `resetKey` : changer d'adresse efface l'erreur, pour que la page suivante s'affiche normalement.
 */
export default class ErrorBoundary extends Component<{ resetKey: string; children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidUpdate(previous: { resetKey: string }) {
    if (this.state.error && previous.resetKey !== this.props.resetKey) this.setState({ error: null });
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Erreur d'affichage de la page", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="stack page-error">
        <ErrorBanner error="Cet écran n'a pas pu s'afficher. Les autres pages restent utilisables." />
        <p className="muted small mono">{this.state.error.message}</p>
        <div className="row">
          <button type="button" onClick={() => this.setState({ error: null })}>Réessayer</button>
        </div>
      </div>
    );
  }
}
