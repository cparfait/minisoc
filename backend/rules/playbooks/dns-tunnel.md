# Tunnel DNS possible

Un poste a demandé des centaines de sous-domaines différents d'un même domaine en quelques minutes. Les tunnels DNS
cachent des commandes ou des données volées dans les noms demandés (ex. `a8f3c1….exemple.xyz`).

1. **Regarder les noms demandés** (page Recherche) :
   `source.ip=<poste> dns.question.registered_domain=<domaine> | head 50`. Des suites aléatoires et longues sont
   typiques d'un tunnel.
2. **Le domaine est-il connu ?** Éditeur légitime (antivirus, télémétrie, CDN) : l'ajouter aux domaines de confiance
   (Paramètres › Détection). Domaine récent ou inconnu : suspect.
3. **Identifier le processus** sur le poste (console HarfangLab : connexions réseau, processus).
4. **Si suspect** : isoler le poste, bloquer le domaine (DNS, pare-feu), l'ajouter aux IOC pour retrouver d'autres
   postes dans l'historique.
