# Assistant IA

L'assistant analyse une alerte ou un événement et répond aux questions sur la situation. Il conseille ; il ne peut
exécuter **aucune** action. Le connecteur est celui de LMU Stats Viewer :

| Fournisseur | Où partent les données | Clé |
| --- | --- | --- |
| OpenAI (GPT) | cloud (États-Unis) | oui |
| Anthropic (Claude) | cloud | oui |
| Google (Gemini) | cloud | oui |
| OpenRouter (passerelle vers des centaines de modèles) | cloud, selon le modèle | oui |
| DeepSeek | cloud (Chine) | oui |
| Mistral | cloud (France / UE) | oui |
| Ollama | **votre réseau** : rien ne sort | non |
| Fournisseur personnalisé compatible OpenAI (Groq, xAI, LM Studio, vLLM, passerelle d'entreprise…) | selon l'adresse | facultative |

Pour un fournisseur dans le cloud, les comptes, postes, adresses IP internes et e-mails sont **pseudonymisés**
avant l'envoi (case « Pseudonymiser », cochée par défaut) et restitués à l'affichage.

## Étapes
1. Onglet **Configuration** › *Fournisseurs d'IA* : cliquer **Utiliser** sur le fournisseur choisi.
2. Coller sa **clé d'API** et l'enregistrer (une clé par fournisseur, chiffrée, jamais réaffichée).
   - Ollama : renseigner plus bas « Adresse du serveur Ollama » (ex. `http://serveur-ia:11434`).
   - Fournisseur absent de la liste : **+ Ajouter un fournisseur personnalisé** (nom, adresse de base se terminant en
     général par `/v1`, clé facultative pour un serveur local).
3. **Modèle** : le Mini-SOC lit la liste réelle des modèles chez le fournisseur (bouton « Actualiser la liste ») ;
   choisir dans la liste, ou « Saisir manuellement… » pour un modèle tout juste sorti. Le lien « Liste officielle
   des modèles » ouvre la documentation du fournisseur. **Enregistrer le modèle.**
4. Autoriser l'accès HTTPS sortant du serveur du Mini-SOC vers l'adresse du fournisseur (sauf modèle local).
5. Activer l'intégration (interrupteur de la fiche), puis **Tester**.

## Vérifier
- Sur une alerte : bloc « Assistant IA » › Analyser.
- Sur un événement déplié : bouton « Analyser avec l'IA ».

## Bon à savoir
- Chaque demande est tracée dans le journal d'audit (qui, quoi, quel fournisseur et modèle), sans le contenu.
- Limite : 40 demandes par heure et par utilisateur.
- Modèle local lent au premier appel : chargement en mémoire (jusqu'à plusieurs minutes si la carte graphique est
  partagée avec d'autres usages).
- Message « réponse tronquée » : augmenter « Longueur maximale de réponse ».
