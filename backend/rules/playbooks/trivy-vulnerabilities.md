# Vulnérabilités signalées par Trivy

## Vérifier
1. Page **Vulnérabilités** : rechercher la CVE citée ; la fiche indique les images ou serveurs touchés, le
   composant, la version installée et la version corrigée.
2. Faille du catalogue KEV : elle est exploitée activement. Le service concerné est-il joignable (exposé à
   Internet, ouvert aux postes) ? Une faille dans un composant non exposé (base de données interne) pèse moins.
3. Chercher des traces d'exploitation : alertes EDR ou IPS sur la machine, page Recherche (`host.name:<machine>`).

## Agir
1. **Images du Mini-SOC** : appliquer le dernier paquet de mise à jour (`sudo minisoc-update`), qui reconstruit
   les images à partir des versions corrigées ; puis Intégrations › Trivy › « Analyser maintenant ».
2. **Serveur Docker** : mettre à jour l'image concernée (`docker compose pull` puis `up -d`, ou reconstruction de
   l'image si elle est produite en interne) ; composant du système : mise à jour des paquets.
3. Pas encore de correctif utilisable : mesure de contournement (filtrage, désactivation du service) et suivi dans
   un incident.

Trivy signale ce qui est **présent**, pas ce qui est exploitable : une faille dans une fonction jamais appelée ou
un service non exposé peut être acceptée en connaissance de cause (exception sur l'alerte, avec un commentaire).
Le rapport suivant (hebdomadaire, ou à la demande) montre si la faille a disparu.
