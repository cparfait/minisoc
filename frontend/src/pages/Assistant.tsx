import { Sparkles } from "lucide-react";
import AIConversation from "../components/AIConversation";
import { Card, PageHeader } from "../components/ui";

const EXAMPLES = [
  "Fais-moi un point de situation : qu'est-ce qui est le plus urgent ?",
  "Le botnet qui vise le VPN a-t-il réussi à se connecter ?",
  "Quelles mesures prendre sur le Sophos XGS contre ces attaques ?",
];

export default function Assistant() {
  return (
    <>
      <PageHeader title="Assistant IA" icon={Sparkles} subtitle="Questions sur la situation, en lecture seule" />
      <p className="muted">
        Posez vos questions sur la situation en cours : l'assistant voit les alertes ouvertes, l'état des sources et
        l'activité d'authentification des dernières 24 h. Pour analyser une alerte précise, utilisez le bouton
        « Analyser avec l'IA » dans sa fiche.
      </p>
      <Card>
        <AIConversation path="/ai/chat" placeholder="Votre question (Entrée pour envoyer, Maj+Entrée pour aller à la ligne)" />
        <div className="ai-examples">
          {EXAMPLES.map((q) => <span key={q} className="muted small">« {q} »</span>)}
        </div>
      </Card>
    </>
  );
}
